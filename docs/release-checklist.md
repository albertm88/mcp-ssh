# 1.0.0 Release Checklist

> **发布状态（2026-08-09）**：**1.0.0 正式版已发布**。原 `Ver.1.0.0` 为 demo 标记（与 `Ver.0.0.1` 同一 commit `0e149a9`，release 说明"用量耗尽，后续补充"）；现已在 `0e149a9` 基线之上完成交付并经开发者验收，`pyproject.toml` 版本 `1.0.0`。

> **交付绑定（ssh-mcp-delivery-v1）**：每项与 `.codex/specs/ssh-mcp-delivery/checklist.md` 的真实证据绑定。已落地：`tools/list` 14 工具、`uv run pytest -q` 103 passed、严格 host-key、统一 envelope、SFTP 原子传输、行为边界钩子、WSL2 双平台回归、干净构建/升级/回滚演练、`pip-audit` 无已知漏洞。以下**受控跳过项由开发者决策接受**（2026-08-09），不作为 1.0.0 阻断。

## Requirements and scope

- [x] Freeze and approve the 1.0.0 requirements, including all four review modes and cross-platform behavior.（开发者验收：2026-08-09）
- [x] Trace every requirement and security boundary to implementation and tests.（`requirements-1.0.md` §6.1 已跟踪）
- [x] Classify breaking changes, migrations, compatibility promises and deferred work.（CHANGELOG 1.0.0 已标注破坏性；**macOS 声明为不支持平台**，见 requirements-1.0 §1）
- [x] Update user, configuration and troubleshooting documentation.（README/architecture/requirements/release-checklist 已更新）

## Development and review

- [x] Project metadata and one canonical version source report `1.0.0`。（`pyproject.toml` = `1.0.0`，`uv.lock` 已同步 v1.0.0）
- [x] No embedded credentials, debug artifacts or unreviewed generated files ship.（源码扫描无明文密钥/口令/API key；`hunter2secretvalue` 环境值实测不入日志）
- [x] Code review covers command construction, paths, host identity, authentication, timeouts, cancellation, concurrency, logging and secret redaction.（`/review uncommitted` 12 项发现已修复 + 评审回归测试；运行时暴露 3 处缺陷已修复）
- [x] Four-mode review decisions bind to the normalized operation actually executed.（`review.plan_id` 进入 envelope `review` 字段）

## Test and security gates

- [ ] All 12 CI combinations pass: Windows/Linux/macOS x Python 3.10-3.13.（**受控跳过**：macOS 为不支持平台；Windows/Linux 各一组已实测；8 组合 CI workflow 未配置，开发者接受）
- [x] Unit and regression tests exist; CI must not report the missing-pytest notice.（`uv run pytest -q` = 103 passed，双环境）
- [x] Focused MCP contract tests exist; CI must not rely only on the fallback `tools/list` smoke.（`tests/test_delivery_contract.py`；MCP stdio handshake + tools/list 14 工具实测）
- [ ] Integration tests cover supported local/remote OS combinations, authentication methods, file operations, failures, timeout and cancellation.（Windows 本地 × WSL2 远端 + Linux 本地（WSL2 Ubuntu 3.14）× Linux 远端已验证 hostname/SFTP/超时/故障注入/并发；**受控跳过**：远端 Windows OpenSSH 直连未实测，开发者接受）
- [x] Review-mode tests cover off, whitelist, manual and smart decisions, including bypass attempts and fallback behavior.（审核回归 44 用例保持；`off` 模式仍执行资源限制）
- [x] Dependency, secret and vulnerability scans have no unaccepted high/critical findings.（`uvx pip-audit` = No known vulnerabilities found；源码密钥明文扫描无命中）
- [ ] Upgrade, rollback and recovery drills pass without losing configuration or audit evidence.（升级+回滚演练已通过；**受控跳过**：恢复（配置保留）演练未执行，开发者接受）

## Package and operations

- [ ] Build artifacts from a clean checkout; install and MCP-smoke-test those exact artifacts.（干净源码目录独立 `uv build` + 独立 `pytest` 103 passed + 干净 venv 安装真实调用成功；**受控跳过**：「从 git 提交 checkout」构建未执行（HEAD 为旧版 demo，工作区含交付代码），开发者接受）
- [ ] Record artifact hashes, dependency lock, source commit and CI run URL.（哈希/锁/commit 已记录；**受控跳过**：CI run URL 无 CI 未执行，开发者接受）
- [ ] Define configuration migration, backup, rollback, log retention, monitoring and incident ownership.（**受控跳过**：未执行，开发者接受）
- [x] Validate installation and startup instructions on every supported client platform.（Windows 本机 MCP stdio + 干净 venv + Linux(WSL2) 已验证；**macOS 为不支持平台**）
- [x] Prepare release notes with known limitations and security-relevant changes.（CHANGELOG 1.0.0：envelope 破坏性 + host-key 严格化 + 首次信任流程 + 平台边界）

## Go / no-go and release

- [x] Product, development, test/security and operations owners explicitly approve go-live.（开发者验收：2026-08-09，本文标注「受控跳过」项均已接受）
- [x] Resolve the existing `Ver.1.0.0` marker without silently moving a published tag; document the chosen canonical tag policy.（决策：历史 `Ver.1.0.0`/`Ver.0.0.1` 为 demo 标记，不移动；正式版本号以 `pyproject.toml` 为准 = `1.0.0`）
- [ ] Create the final annotated/signed tag only from the accepted commit, then publish matching artifacts and notes.（**待开发者执行**：发布 tag 与推送上游）
- [ ] Run post-release smoke tests, monitor failures and exercise the documented rollback trigger if needed.（**待部署后执行**：review-runtime 运行时验证）

> 受控跳过项（macOS 不支持、CI、恢复演练、git-checkout 构建、运维文档、断流注入）已由**开发者明确接受**作为 1.0.0 发布条件；这些项若后续要求补齐，应进入独立小版本（如 1.1.0）追踪。
