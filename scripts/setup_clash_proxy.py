#!/usr/bin/env python3
"""
Setup proxy from a Clash/Mihomo subscription URL for check-in CI.

Parses Clash YAML subscription (proxies: list), tests each node in
parallel via xray with WAF detection, picks the first working one.

Environment variables:
 CLASH_SUBSCRIPTION_URL   Subscription URL (also falls back to PROXY_SUBSCRIPTION_URL)
 XRAY_VERSION             Xray-core version tag (default: v1.8.24)
 PROXY_PORT               SOCKS port (default: 7890)
 PROXY_TEST_URL           Health check target (default: https://agentrouter.org)
 PROXY_REQUIRED           Exit 1 on failure when 'true'
 RUNNER_TEMP              Temp directory (default: /tmp)
 GITHUB_ENV               Path to GITHUB_ENV file (GitHub Actions)
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.resolve()))

import base64
import concurrent.futures
import json
import os
import queue
import subprocess
import threading
import time
import zipfile
from typing import Any

import yaml  # type: ignore[import-untyped]

WAF_KEYWORDS = [
	'captcha',
	'滑块',
	'验证',
	'just a moment',
	'阿里云 Web 应用防火墙',
	'Web Application Firewall',
	'WAF',
	'人机识别',
	'安全检查',
	'安全验证',
]
XRAY_BASE_URL = 'https://github.com/XTLS/Xray-core/releases/download/{version}/Xray-linux-64.zip'
DEFAULT_XRAY_VERSION = 'v1.8.24'
DEFAULT_PORT = 7890
DEFAULT_TEST_URL = 'https://agentrouter.org'
MAX_WORKERS = 30


def log(msg: str) -> None:
	print(msg, flush=True)


# ── xray helpers ──────────────────────────────────────────────


def download_xray(proxy_dir: Path, version: str) -> Path:
	xray_bin = proxy_dir / 'xray'
	if xray_bin.exists():
		log(f'[INFO] xray binary already exists at {xray_bin}')
		return xray_bin

	url = XRAY_BASE_URL.format(version=version)
	archive_path = proxy_dir / 'xray.zip'

	log(f'[INFO] Downloading xray {version}...')
	subprocess.run(
		['curl', '--retry', '3', '--retry-delay', '5', '--retry-all-errors', '-fsSL', '-o', str(archive_path), url],
		check=True,
	)

	log('[INFO] Extracting xray...')
	with zipfile.ZipFile(archive_path) as zf:
		zf.extractall(proxy_dir)

	xray_bin.chmod(0o755)
	archive_path.unlink()
	log(f'[SUCCESS] xray ready at {xray_bin}')
	return xray_bin


# ── Clash subscription parsing ───────────────────────────────


def fetch_clash_subscription(url: str) -> list[dict]:
	"""Fetch and parse a Clash YAML subscription, returning a list of node config dicts."""
	log('[INFO] Fetching subscription...')
	try:
		result = subprocess.run(
			['curl', '-sSL', '--retry', '3', '--retry-delay', '5', url],
			capture_output=True,
			text=True,
			timeout=30,
		)
		if result.returncode != 0:
			log(f'[FAILED] Failed to fetch subscription: curl exit {result.returncode}')
			return []
		raw = result.stdout.strip()
	except subprocess.TimeoutExpired:
		log('[FAILED] Subscription fetch timed out')
		return []

	if not raw:
		log('[FAILED] Empty subscription response')
		return []

	# Try base64 decode first (some Clash subs are base64-encoded v2ray-style lists)
	decoded: str | None = None
	for pad in ['', '==', '=']:
		try:
			tmp = base64.b64decode(raw + pad).decode('utf-8')
			decoded = tmp
			break
		except Exception:
			continue

	content = decoded or raw

	# Try parse as YAML
	try:
		data = yaml.safe_load(content)
	except yaml.YAMLError:
		log('[FAILED] Subscription is not valid YAML')
		return []

	if isinstance(data, list):
		proxies_raw = data
	elif isinstance(data, dict):
		proxies_raw = data.get('proxies') or []
		if not proxies_raw:
			log('[FAILED] No proxies key found in subscription YAML')
			return []
	else:
		log('[FAILED] Unexpected subscription format')
		return []

	nodes: list[dict] = []
	for entry in proxies_raw:
		if not isinstance(entry, dict):
			continue
		node = parse_clash_proxy(entry)
		if node:
			nodes.append(node)

	log(f'[INFO] Parsed {len(nodes)} node(s) from subscription')
	return nodes


CLASH_TYPE_TO_PROTOCOL: dict[str, str] = {
	'vmess': 'vmess',
	'vless': 'vless',
	'ss': 'shadowsocks',
	'trojan': 'trojan',
}


def parse_clash_proxy(entry: dict) -> dict | None:
	"""Convert a single Clash YAML proxy entry to our internal node dict."""
	clash_type = entry.get('type', '').lower()
	protocol = CLASH_TYPE_TO_PROTOCOL.get(clash_type)
	if not protocol:
		return None

	node: dict[str, Any] = {
		'protocol': protocol,
		'add': entry.get('server', ''),
		'port': str(entry.get('port', 443)),
		'ps': entry.get('name', 'unknown'),
	}

	if clash_type == 'vmess':
		node['id'] = entry.get('uuid', '')
		node['aid'] = str(entry.get('alterId', 0))
		node['scy'] = entry.get('cipher', 'auto')

	elif clash_type == 'vless':
		node['id'] = entry.get('uuid', '')
		node['flow'] = entry.get('flow', '')
		node['encryption'] = 'none'

	elif clash_type == 'ss':
		node['id'] = entry.get('password', '')
		node['aid'] = entry.get('cipher', 'aes-256-gcm')

	elif clash_type == 'trojan':
		node['id'] = entry.get('password', '')

	elif clash_type == 'socks5':
		node['id'] = entry.get('password', '') or entry.get('username', '_')
		node['aid'] = entry.get('username', '')

	# Network
	net = entry.get('network', 'tcp')
	node['net'] = net

	# TLS
	tls_val = 'tls' if entry.get('tls', False) else ''
	node['tls'] = tls_val

	# WS
	if net == 'ws':
		ws_opts = entry.get('ws-opts', {}) or {}
		node['path'] = ws_opts.get('path') or entry.get('ws-path') or ''
		ws_headers = ws_opts.get('headers', {}) or {}
		node['host'] = ws_headers.get('Host') or entry.get('ws-headers', {}).get('Host') or ''

	# gRPC
	elif net == 'grpc':
		node['serviceName'] = (
			entry.get('grpc-service-name') or entry.get('grpc-opts', {}).get('grpc-service-name') or ''
		)

	# H2
	elif net == 'h2':
		node['path'] = entry.get('h2-path', '') or entry.get('h2-opts', {}).get('path', '')
		node['host'] = entry.get('h2-host', '') or entry.get('h2-opts', {}).get('host', '')

	# HTTP
	elif net == 'http':
		node['path'] = entry.get('http-path', '') or ''
		node['host'] = entry.get('http-host', '') or ''

	# KCP
	elif net == 'kcp':
		node['type'] = entry.get('header-type', 'none')  # used by build_stream_settings
		node['seed'] = entry.get('seed', '')

	# QUIC
	elif net == 'quic':
		node['type'] = entry.get('header-type', 'none')
		node['mode'] = entry.get('mode', '')

	# TLS / fingerprint
	node['sni'] = entry.get('sni', '') or entry.get('servername', '') or ''
	node['fp'] = entry.get('client-fingerprint', '') or entry.get('fingerprint', '') or 'chrome'

	# Reality
	node['pbk'] = entry.get('reality-public-key', '') or entry.get('pbk', '') or ''
	node['sid'] = entry.get('reality-short-id', '') or entry.get('sid', '') or ''

	return node


# ── xray config builder (mirrors setup_v2ray_proxy) ──────────


def build_outbound(node: dict) -> dict | None:
	protocol = node.get('protocol', 'vmess')
	addr = node.get('add', '')
	port_str = node.get('port', '443')
	try:
		port = int(port_str)
	except ValueError:
		port = 443

	if protocol == 'vmess':
		outbound: dict = {
			'protocol': 'vmess',
			'settings': {
				'vnext': [
					{
						'address': addr,
						'port': port,
						'users': [
							{
								'id': node.get('id', ''),
								'alterId': int(node.get('aid', '0')),
								'security': node.get('scy', 'auto'),
							}
						],
					}
				],
			},
		}
	elif protocol == 'vless':
		outbound = {
			'protocol': 'vless',
			'settings': {
				'vnext': [
					{
						'address': addr,
						'port': port,
						'users': [
							{
								'id': node.get('id', ''),
								'encryption': node.get('encryption', 'none'),
								'flow': node.get('flow', ''),
							}
						],
					}
				],
			},
		}
	elif protocol == 'shadowsocks':
		method = node.get('aid', 'aes-256-gcm')
		password = node.get('id', '')
		outbound = {
			'protocol': 'shadowsocks',
			'settings': {
				'servers': [
					{
						'address': addr,
						'port': port,
						'method': method if method else 'aes-256-gcm',
						'password': password,
						'level': 0,
					}
				],
			},
		}
	elif protocol == 'trojan':
		outbound = {
			'protocol': 'trojan',
			'settings': {
				'servers': [
					{
						'address': addr,
						'port': port,
						'password': node.get('id', ''),
						'level': 0,
					}
				],
			},
		}
	else:
		return None

	stream = build_stream_settings(node)
	if stream:
		outbound['streamSettings'] = stream

	return outbound


def build_stream_settings(node: dict) -> dict:
	net = node.get('net', 'tcp')
	tls_enabled = node.get('tls', '') in ('tls', '1', 'true')
	security = 'tls' if tls_enabled else 'none'

	stream: dict = {'network': net, 'security': security}

	if tls_enabled:
		tls_settings: dict = {}
		sni = node.get('sni') or node.get('host') or ''
		if sni:
			tls_settings['serverName'] = sni
		tls_settings['fingerprint'] = node.get('fp', 'chrome')
		tls_settings['alpn'] = ['h2', 'http/1.1']
		stream['tlsSettings'] = tls_settings

	if net == 'ws':
		ws_settings: dict = {}
		path = node.get('path', '')
		if path:
			ws_settings['path'] = path
		host = node.get('host', '')
		if host:
			ws_settings['headers'] = {'Host': host}
		stream['wsSettings'] = ws_settings

	elif net == 'kcp':
		kcp_settings: dict = {'mtu': 1350, 'tti': 50, 'uplinkCapacity': 12, 'downlinkCapacity': 100}
		header_type = node.get('type', 'none')
		kcp_settings['header'] = {'type': header_type}
		seed = node.get('seed', '')
		if seed:
			kcp_settings['seed'] = seed
		stream['kcpSettings'] = kcp_settings

	elif net == 'h2':
		h2_settings: dict = {}
		path = node.get('path', '')
		if path:
			h2_settings['path'] = path
		host = node.get('host', '')
		if host:
			h2_settings['host'] = [host]
		stream['httpSettings'] = h2_settings

	elif net == 'quic':
		quic_settings: dict = {}
		header_type = node.get('type', 'none')
		quic_settings['header'] = {'type': header_type}
		for k in ('key', 'security'):
			val = node.get(k, '')
			if val:
				quic_settings[k] = val
		stream['quicSettings'] = quic_settings

	elif net == 'grpc':
		grpc_settings: dict = {}
		svc = node.get('serviceName', '')
		if svc:
			grpc_settings['serviceName'] = svc
		stream['grpcSettings'] = grpc_settings

	return stream


def build_xray_config(node: dict, socks_port: int) -> dict:
	outbound = build_outbound(node)
	if outbound is None:
		raise ValueError(f'Unsupported protocol: {node.get("protocol")}')

	return {
		'log': {'loglevel': 'warning'},
		'inbounds': [
			{
				'protocol': 'socks',
				'port': socks_port,
				'listen': '127.0.0.1',
				'settings': {'auth': 'noauth', 'udp': False},
			}
		],
		'outbounds': [outbound],
	}


# ── xray process & probe ─────────────────────────────────────


def start_xray(xray_bin: Path, config_path: Path, cwd: Path) -> subprocess.Popen:
	log_path = cwd / 'xray.log'
	log_file = open(log_path, 'w')
	log(f'[INFO] Starting xray (config: {config_path.name})...')

	proc = subprocess.Popen(
		[str(xray_bin), 'run', '-c', str(config_path)],
		stdout=log_file,
		stderr=subprocess.STDOUT,
		cwd=str(cwd),
		start_new_session=True,
	)
	return proc


def check_proxy(port: int, test_url: str) -> tuple[bool, bool]:
	proxy = f'socks5://127.0.0.1:{port}'
	try:
		result = subprocess.run(
			['curl', '-sS', '-x', proxy, '--max-time', '15', test_url],
			capture_output=True,
			text=True,
			timeout=20,
		)
		if result.returncode != 0:
			log(f'[WARN] Health check: curl exit {result.returncode}')
			return False, False

		body = result.stdout + result.stderr
		body_lower = body.lower()
		for kw in WAF_KEYWORDS:
			if kw.lower() in body_lower:
				log(f'[WARN] WAF detected: keyword "{kw}" found in response')
				return True, True

		return True, False
	except subprocess.TimeoutExpired:
		log('[WARN] Health check timed out')
		return False, False
	except Exception as e:
		log(f'[WARN] Health check error: {e}')
		return False, False


def node_display_name(node: dict) -> str:
	return str(node.get('ps') or node.get('add', 'unknown'))


class PortPool:
	def __init__(self, start: int, count: int):
		self._queue: queue.Queue[int] = queue.Queue()
		for i in range(count):
			self._queue.put(start + i)

	def acquire(self) -> int:
		return self._queue.get()

	def release(self, port: int) -> None:
		self._queue.put(port)


def probe_node_worker(
	node: dict,
	xray_bin: Path,
	proxy_dir: Path,
	test_url: str,
	port_pool: PortPool,
	stop_event: threading.Event,
	idx: int,
	total: int,
) -> tuple[bool, bool, str, int, subprocess.Popen | None]:
	name = node_display_name(node)
	proto = node.get('protocol', 'vmess')

	if stop_event.is_set():
		return False, False, name, 0, None

	log(f'[PROCESSING] Node {idx}/{total}: {name} ({proto})')

	port = port_pool.acquire()
	proc: subprocess.Popen | None = None
	try:
		config = build_xray_config(node, port)
		config_path = proxy_dir / f'config_{port}.json'
		with open(config_path, 'w') as f:
			json.dump(config, f, indent=2)

		proc = start_xray(xray_bin, config_path, proxy_dir)
		time.sleep(2)

		if proc.poll() is not None:
			return False, False, name, port, None

		reachable, waf = check_proxy(port, test_url)

		if waf:
			log(f'[WARN] Node "{name}" triggered WAF')
		if not reachable and not waf:
			log(f'[WARN] Node "{name}" unreachable')

		if waf or not reachable:
			proc.terminate()
			try:
				proc.wait(timeout=3)
			except subprocess.TimeoutExpired:
				proc.kill()
				proc.wait()
			return reachable, waf, name, port, None

		return reachable, waf, name, port, proc
	finally:
		if proc is None or proc.poll() is not None:
			port_pool.release(port)


# ── main ─────────────────────────────────────────────────────


def main() -> None:
	subscription_url = os.environ.get('CLASH_SUBSCRIPTION_URL', '').strip()
	if not subscription_url:
		subscription_url = os.environ.get('PROXY_SUBSCRIPTION_URL', '').strip()

	xray_version = os.environ.get('XRAY_VERSION', DEFAULT_XRAY_VERSION).strip()
	proxy_port_str = os.environ.get('PROXY_PORT', str(DEFAULT_PORT)).strip()
	test_url = os.environ.get('PROXY_TEST_URL', DEFAULT_TEST_URL).strip()
	proxy_required = os.environ.get('PROXY_REQUIRED', 'false').strip().lower() in ('true', '1')
	runner_temp = os.environ.get('RUNNER_TEMP', '/tmp')
	github_env = os.environ.get('GITHUB_ENV', '').strip()

	try:
		proxy_port = int(proxy_port_str)
	except ValueError:
		log(f'[FAILED] Invalid PROXY_PORT: {proxy_port_str}')
		sys.exit(1)

	if not subscription_url:
		log('[INFO] CLASH_SUBSCRIPTION_URL not set, skip proxy setup')
		sys.exit(0)

	proxy_dir = Path(runner_temp) / 'checkin-proxy'
	proxy_dir.mkdir(parents=True, exist_ok=True)

	xray_bin = download_xray(proxy_dir, xray_version)

	nodes = fetch_clash_subscription(subscription_url)
	if not nodes:
		log('[FAILED] No valid nodes found in subscription')
		sys.exit(1 if proxy_required else 0)

	log(f'[INFO] Testing {len(nodes)} node(s) against {test_url} (max {MAX_WORKERS} concurrent)')

	port_pool = PortPool(proxy_port, MAX_WORKERS)
	stop_event = threading.Event()
	found_node: tuple[int, subprocess.Popen, str] | None = None

	executor = concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS)
	try:
		fut_map: dict[concurrent.futures.Future, dict] = {}
		for i, node in enumerate(nodes):
			fut = executor.submit(
				probe_node_worker,
				node,
				xray_bin,
				proxy_dir,
				test_url,
				port_pool,
				stop_event,
				i + 1,
				len(nodes),
			)
			fut_map[fut] = node

		for fut in concurrent.futures.as_completed(fut_map):
			if stop_event.is_set():
				break

			try:
				reachable, waf, name, port, proc = fut.result()
			except Exception:
				continue
			if reachable and not waf and proc is not None:
				stop_event.set()
				found_node = (port, proc, name)
				for ff in fut_map:
					ff.cancel()
				break
	finally:
		executor.shutdown(wait=False)

	if found_node is None:
		log('[FAILED] All nodes failed or triggered WAF')
		sys.exit(1 if proxy_required else 0)

	port, proc, name = found_node
	pid_path = proxy_dir / 'xray.pid'
	with open(pid_path, 'w') as fh:
		fh.write(str(proc.pid))

	proxy_url = f'socks5://127.0.0.1:{port}'
	log(f'[SUCCESS] AgentRouter reachable without WAF via node: {name}')
	log(f'[SUCCESS] Proxy is ready: {proxy_url}')

	if github_env:
		try:
			with open(github_env, 'a') as fh:
				fh.write(f'CHECKIN_PROXY_URL={proxy_url}\n')
			log(f'[INFO] CHECKIN_PROXY_URL written to {github_env}')
		except Exception as e:
			log(f'[WARN] Failed to write CHECKIN_PROXY_URL: {e}')

	os._exit(0)


if __name__ == '__main__':
	main()
