#!/usr/bin/env python3
"""
Setup v2ray/xray proxy from a subscription URL for check-in CI.

Environment variables:
  V2RAY_SUBSCRIPTION_URL   Subscription URL (required for v2ray mode)
  XRAY_VERSION              Xray-core version tag (default: v1.8.24)
  PROXY_PORT                SOCKS port (default: 7891)
  PROXY_TEST_URL            Health check target (default: https://agentrouter.org)
  PROXY_REQUIRED            Exit 1 on failure when 'true'
  RUNNER_TEMP               Temp directory (default: /tmp)
  GITHUB_ENV                Path to GITHUB_ENV file (GitHub Actions)
"""

from __future__ import annotations

import base64
import json
import os
import subprocess
import sys
import time
import zipfile
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse

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
DEFAULT_PORT = 7891
DEFAULT_TEST_URL = 'https://agentrouter.org'


def log(msg: str) -> None:
	print(msg, flush=True)


def download_xray(proxy_dir: Path, version: str) -> Path:
	"""Download and extract xray-core binary."""
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


def fetch_subscription(url: str) -> list[dict]:
	"""Fetch and parse v2ray subscription, returning list of node config dicts."""
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

	decoded = None
	for attempt in [raw, raw + '==', raw + '=']:
		try:
			decoded = base64.b64decode(attempt).decode('utf-8')
			break
		except Exception:
			continue

	if decoded:
		lines = decoded.strip().splitlines()
	else:
		lines = raw.splitlines()

	nodes = []
	for line_data in lines:
		line_data = line_data.strip()
		if not line_data or line_data.startswith('#'):
			continue
		node = parse_node_uri(line_data)
		if node:
			nodes.append(node)

	log(f'[INFO] Parsed {len(nodes)} node(s) from subscription')
	return nodes


def parse_node_uri(uri: str) -> dict | None:
	"""Parse a single proxy URI into a node config dict."""
	if uri.startswith('vmess://'):
		return parse_vmess(uri)
	elif uri.startswith('vless://'):
		return parse_vless(uri)
	elif uri.startswith('ss://'):
		return parse_ss(uri)
	elif uri.startswith('trojan://'):
		return parse_trojan(uri)
	return None


def parse_vmess(uri: str) -> dict | None:
	"""Parse vmess:// URI."""
	try:
		b64 = uri[len('vmess://') :]
		raw = b64
		for pad in ['', '==', '=']:
			try:
				raw = base64.b64decode(b64 + pad).decode('utf-8')
				break
			except Exception:
				continue
		data = json.loads(raw)
	except Exception:
		return None

	field_map = {
		'add': 'add',
		'port': 'port',
		'id': 'id',
		'aid': 'aid',
		'scy': 'scy',
		'net': 'net',
		'type': 'type',
		'host': 'host',
		'path': 'path',
		'tls': 'tls',
		'ps': 'ps',
		'sni': 'sni',
		'fp': 'fp',
		'alpn': 'alpn',
	}

	node: dict = {'protocol': 'vmess'}
	for src, dst in field_map.items():
		val = data.get(src)
		if val is not None:
			node[dst] = val
	return node


def parse_vless(uri: str) -> dict | None:
	"""Parse vless:// URI."""
	try:
		parsed = urlparse(uri)
		user_info = parsed.netloc.split('@', 1)
		if len(user_info) != 2:
			return None
		node_id, host_part = user_info
		host_port = host_part.rsplit(':', 1)
		host = host_port[0]
		port = int(host_port[1]) if len(host_port) == 2 and host_port[1].isdigit() else 443

		params = parse_qs(parsed.query)

		def g(k: str, default: str = '') -> str:
			return params.get(k, [default])[0]

		return {
			'protocol': 'vless',
			'id': node_id,
			'add': host,
			'port': str(port),
			'aid': '0',
			'net': g('type', 'tcp'),
			'tls': 'tls' if g('security') in ('tls', 'xtls', 'reality') else '',
			'host': g('host') or g('sni'),
			'path': unquote(g('path')),
			'sni': g('sni'),
			'fp': g('fp', 'chrome'),
			'encryption': g('encryption', 'none'),
			'flow': g('flow', ''),
			'type': g('headerType', 'none'),
			'ps': g('ps') or g('remark'),
			'serviceName': g('serviceName'),
			'mode': g('mode'),
			'seed': g('seed'),
			'pbk': g('pbk'),
			'sid': g('sid'),
		}
	except Exception:
		return None


def parse_ss(uri: str) -> dict | None:
	"""Parse ss:// URI."""
	try:
		no_scheme = uri[len('ss://') :]
		at_pos = no_scheme.find('@')
		if at_pos == -1:
			try:
				decoded = base64.b64decode(no_scheme + '=' * (4 - len(no_scheme) % 4)).decode('utf-8')
				host_port = decoded.rsplit('@', 1)[-1]
				method_pass = decoded.split('@')[0]
			except Exception:
				return None
		else:
			method_pass_b64 = no_scheme[:at_pos]
			host_port_str = no_scheme[at_pos + 1 :]
			try:
				method_pass = base64.b64decode(method_pass_b64 + '=' * (4 - len(method_pass_b64) % 4)).decode('utf-8')
			except Exception:
				method_pass = method_pass_b64
			host_port = host_port_str

		hp = host_port.rsplit(':', 1)
		if len(hp) != 2:
			return None

		mp = method_pass.split(':', 1)
		return {
			'protocol': 'shadowsocks',
			'add': hp[0],
			'port': hp[1],
			'id': mp[1] if len(mp) == 2 else method_pass,
			'aid': mp[0] if len(mp) == 2 else '',
			'net': 'tcp',
			'tls': '',
		}
	except Exception:
		return None


def parse_trojan(uri: str) -> dict | None:
	"""Parse trojan:// URI."""
	try:
		parsed = urlparse(uri)
		user_info = parsed.netloc.split('@', 1)
		password = user_info[0]
		host_part = user_info[1] if len(user_info) == 2 else ''
		host_port = host_part.rsplit(':', 1) if host_part else ['', '443']
		host = host_port[0]
		port = int(host_port[1]) if host_port[1].isdigit() else 443

		params = parse_qs(parsed.query)

		def g(k: str, default: str = '') -> str:
			return params.get(k, [default])[0]

		return {
			'protocol': 'trojan',
			'id': password,
			'add': host,
			'port': str(port),
			'net': g('type', 'tcp'),
			'tls': 'tls',
			'host': g('sni') or g('host') or host,
			'sni': g('sni') or g('host') or host,
			'fp': g('fp', 'chrome'),
			'path': unquote(g('path')),
			'serviceName': g('serviceName'),
			'flow': g('flow', ''),
		}
	except Exception:
		return None


def build_outbound(node: dict) -> dict:
	"""Build xray outbound config from a parsed node dict."""
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
		raise ValueError(f'Unsupported protocol: {protocol}')

	stream = build_stream_settings(node)
	if stream:
		outbound['streamSettings'] = stream

	return outbound


def build_stream_settings(node: dict) -> dict:
	"""Build xray streamSettings from a parsed node dict."""
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
	"""Build complete xray JSON config from a parsed node."""
	outbound = build_outbound(node)

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


def start_xray(xray_bin: Path, config_path: Path, cwd: Path) -> subprocess.Popen:
	"""Start xray as a background process (detached)."""
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
	"""Test proxy health. Returns (reachable, waf_detected)."""
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


def main() -> None:
	subscription_url = os.environ.get('V2RAY_SUBSCRIPTION_URL', '').strip()
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
		log('[INFO] V2RAY_SUBSCRIPTION_URL not set, skip v2ray proxy setup')
		sys.exit(0)

	proxy_dir = Path(runner_temp) / 'checkin-proxy'
	proxy_dir.mkdir(parents=True, exist_ok=True)

	xray_bin = download_xray(proxy_dir, xray_version)

	nodes = fetch_subscription(subscription_url)
	if not nodes:
		log('[FAILED] No valid nodes found in subscription')
		sys.exit(1 if proxy_required else 0)

	log(f'[INFO] Testing {len(nodes)} node(s) against {test_url}')

	for i, node in enumerate(nodes):
		name = node_display_name(node)
		proto = node.get('protocol', 'vmess')
		log(f'[PROCESSING] Node {i + 1}/{len(nodes)}: {name} ({proto})')

		config = build_xray_config(node, proxy_port)
		config_path = proxy_dir / 'config.json'
		with open(config_path, 'w') as f:
			json.dump(config, f, indent=2)

		proc = start_xray(xray_bin, config_path, proxy_dir)
		time.sleep(3)

		if proc.poll() is not None:
			log(f'[FAILED] xray exited immediately for node {name}')
			continue

		reachable, waf = check_proxy(proxy_port, test_url)

		if reachable and not waf:
			pid_path = proxy_dir / 'xray.pid'
			with open(pid_path, 'w') as f:
				f.write(str(proc.pid))

			proxy_url = f'socks5://127.0.0.1:{proxy_port}'
			log(f'[SUCCESS] AgentRouter reachable without WAF via node: {name}')
			log(f'[SUCCESS] Proxy is ready: {proxy_url}')

			if github_env:
				try:
					with open(github_env, 'a') as f:
						f.write(f'CHECKIN_PROXY_URL={proxy_url}\n')
					log(f'[INFO] CHECKIN_PROXY_URL written to {github_env}')
				except Exception as e:
					log(f'[WARN] Failed to write CHECKIN_PROXY_URL: {e}')

			sys.exit(0)

		proc.terminate()
		try:
			proc.wait(timeout=5)
		except subprocess.TimeoutExpired:
			proc.kill()
			proc.wait()

		if waf:
			log(f'[WARN] Node "{name}" triggered WAF, trying next...')
		else:
			log(f'[WARN] Node "{name}" unreachable, trying next...')

	log('[FAILED] All nodes failed or triggered WAF')
	sys.exit(1 if proxy_required else 0)


if __name__ == '__main__':
	main()
