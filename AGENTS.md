# AGENTS.md – AnyRouter Check-In

## 包管理 & 运行时

- 包管理器：`uv`（非 pip/poetry/conda）
- Python 版本：3.11（`.python-version`、CI、pyproject.toml 统一）
- 安装：`uv sync --dev`（必须加 `--dev`：测试、lint、类型检查等工具在 dev 组）
- 所有命令通过 `uv run <cmd>` 执行
- uv.lock 与 pyproject.toml 是依赖唯一真相源；CI 用 `uv sync --frozen`

## 代码风格（非默认，容易猜错）

| 项目 | 值                                                        |
| ---- | --------------------------------------------------------- |
| 缩进 | **Tab**（`pyproject.toml` + `.editorconfig`）             |
| 引号 | **单引号**（`[tool.ruff.format] quote-style = "single"`） |
| 行长 | **120** 字符                                              |

- Ruff 同时做 lint 和 format：`uv run ruff check . --fix`
- 格式化检查：`uv run ruff format .`
- 不要用双引号声明字符串，除非字符串本身含单引号

## 关键命令

```bash
uv run checkin.py                          # 主入口
uv run pytest tests/                       # 全部测试
uv run pytest tests/ -k test_name          # 单个测试
uv run mypy .                              # 类型检查
uv run bandit -r . -c pyproject.toml       # 安全扫描
uv run pre-commit run --all-files          # 手动触发 pre-commit
```

## CI 工作流

- `pr-check.yml`：PR 到 `main/master/workflow` 时运行。检查顺序：Ruff lint → Ruff format → **MyPy** → **Bandit** → **Pytest** → Codecov
- **所有检查都 `continue-on-error`**，但最终步骤中 lint/format/pytest 失败会 `exit 1`；mypy/bandit 仅警告
- `checkin.yml`：定时签到（`*/6 * * *`），运行在 `production` environment（GitHub Environments），不运行 lint/test
- pre-commit.ci：CI 中跳过 mypy（慢）

## 项目结构与关键要点

- `checkin.py`：单文件入口，`asyncio.run(main())` 由 `run_main()` 包装
- `utils/config.py`：`ProviderConfig`（定义各平台域/路径/WAF/代理策略）+ `AccountConfig`（邮箱密码优先于 cookies）
- `utils/notify.py`：全局单例 `notify`，多种推送方式
- `utils/browser.py`：基于 `cloakbrowser`（封装 Playwright），不是裸 playwright
- `tests/conftest.py`：`sys.path.insert(0, str(project_root))`，所以测试能直接 `from checkin import x` 和 `from utils.x import y`
- `pytest-asyncio` 配置了 `asyncio_mode = "auto"`，**无需** `@pytest.mark.asyncio` 装饰器也可写 async 测试（虽然部分旧测试仍加着，但不强制）

## Provider 行为差异（容易踩坑）

- **anyrouter**（内置）：`sign_in_path=/api/user/sign_in`，需要手动 POST 签到；`persist_profile=True`（缓存浏览器 profile）
- **agentrouter**（内置）：`sign_in_path=None`，查询 `/api/user/self` 时自动完成签到（不需要额外 POST）；`persist_profile=False`；默认 `use_proxy=true`
- 自定义 provider 可通过环境变量 `PROVIDERS` 传入 JSON（同样要求单行）
- WAF 绕过：`bypass_method: "waf_cookies"` 会启动 `cloakbrowser` 访问登录页获取 WAF cookies

## 环境变量相关

- **`ANYROUTER_ACCOUNTS`**：JSON 数组，**必须是单行**（GitHub Secrets 和 `.env` 均不支持多行 JSON）
- **`PROVIDERS`**：自定义 provider JSON，同样单行
- **`DEBUG_MODE=true`** 开启调试（保存登录截图、打印代理地址/api_user 等敏感信息）
- balance 变化检测：通过 `balance_hash.txt` 缓存 SHA256 摘要；余额 /500000 后才是美元值

## 测试注意事项

- 测试文件 mock 外部请求（httpx、smtp、cloakbrowser），无需真实网络或浏览器
- 真实推送测试：需设置环境变量 `ENABLE_REAL_TEST=true`（默认跳过）
- 覆盖率阈值：project/patch 均 70%，允许 ±5%

## 代理机制

- `get_proxy_server()` 读取 `CHECKIN_PROXY_URL`，按 provider 的 `use_proxy` 决定是否启用
- Python 端不关心代理来源，只认 `CHECKIN_PROXY_URL` 环境变量
- 代理仅注入到浏览器和 HTTP 客户端，不设全局 `HTTP_PROXY`/`HTTPS_PROXY`

### CI 代理（checkin.yml）

通过 Environment variables 中的 `PROXY_TYPE` 选择：

| 值              | 脚本                            | 端口 | 订阅 Secret                                                       |
| --------------- | ------------------------------- | ---- | ----------------------------------------------------------------- |
| `clash`（默认） | `scripts/setup_mihomo_proxy.sh` | 7890 | `CLASH_SUBSCRIPTION_URL`（或向后兼容的 `PROXY_SUBSCRIPTION_URL`） |
| `v2ray`         | `scripts/setup_v2ray_proxy.py`  | 7891 | `V2RAY_SUBSCRIPTION_URL`                                          |

- `scripts/setup_v2ray_proxy.py`：下载 xray-core → 拉取订阅 → 解析 vmess:///vless:///ss:///trojan:// URI → 逐个节点测试 → uTLS `fingerprint: chrome` 防 AI WAF → 找到可用节点后写 `CHECKIN_PROXY_URL`

## `.gitignore` 中的产物

- `balance_hash.txt`（余额缓存）、`.browser_profiles/`（持久化 browser profile）、`checkin_screenshots/`（调试截图）、`.env`、`.venv/`、`htmlcov/`、各种 cache 目录
- 新增功能若产生本地持久文件，应加入 `.gitignore`
