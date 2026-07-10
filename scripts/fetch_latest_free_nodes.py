#!/usr/bin/env python3
"""
从 free-nodes/v2rayfree GitHub 仓库获取最新的免费节点订阅 URL。

使用 GitHub API 列出仓库文件，找到最新的 vYYYYMMDD* 订阅文件，
输出其 raw 下载地址到 stdout，可直接用于 setup_v2ray_proxy.py。

用法：
    export V2RAY_SUBSCRIPTION_URL=$(python scripts/fetch_latest_free_nodes.py)
    python scripts/setup_v2ray_proxy.py

GitHub Actions：
    echo "V2RAY_SUBSCRIPTION_URL=$(python scripts/fetch_latest_free_nodes.py)" >> $GITHUB_ENV

环境变量：
    GITHUB_TOKEN    可选，提高 GitHub API 的速率限制
"""

from __future__ import annotations

import json
import os
import re
import sys
import urllib.error
import urllib.request
from typing import Any

API_URL = 'https://api.github.com/repos/free-nodes/v2rayfree/contents/'
RAW_BASE = 'https://raw.githubusercontent.com/free-nodes/v2rayfree/main'
FILE_PATTERN = re.compile(r'^v\d{8}\d?$')


def log(msg: str) -> None:
	print(msg, file=sys.stderr, flush=True)


def fetch_repo_contents() -> list[dict[str, Any]]:
	req = urllib.request.Request(API_URL)
	req.add_header('Accept', 'application/vnd.github.v3+json')

	token = os.environ.get('GITHUB_TOKEN', '').strip()
	if token:
		req.add_header('Authorization', f'token {token}')

	try:
		with urllib.request.urlopen(req, timeout=15) as resp:
			return json.loads(resp.read().decode('utf-8'))
	except urllib.error.URLError as e:
		log(f'[ERROR] Failed to fetch repo contents: {e}')
		sys.exit(1)
	except json.JSONDecodeError as e:
		log(f'[ERROR] Failed to parse GitHub API response: {e}')
		sys.exit(1)


def find_latest_file(contents: list) -> str | None:
	candidates = []
	for item in contents:
		name = item.get('name', '')
		if FILE_PATTERN.match(name):
			candidates.append(name)

	if not candidates:
		return None

	candidates.sort(reverse=True)
	return candidates[0]


def main() -> None:
	contents = fetch_repo_contents()
	latest = find_latest_file(contents)

	if not latest:
		log('[ERROR] No vYYYYMMDD* files found in the repository')
		sys.exit(1)

	raw_url = f'{RAW_BASE}/{latest}'
	log(f'[INFO] Latest free nodes file: {latest}')
	print(raw_url)


if __name__ == '__main__':
	main()
