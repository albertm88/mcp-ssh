# 1.0.0-fast Release Checklist

> **发布状态**：待执行。本清单对照 Python 版 1.0.0 基线（release-checklist-1.0.0）制定，
> 覆盖 fast（Go 版）的全部发布门禁。

## Requirements and scope

- [x] Freeze and approve the fast requirements: 8 MCP tools, 4 review modes, cross-platform behavior.
- [x] Trace every requirement to implementation and tests（README 工具表 ↔ `internal/server/tools.go` ↔ `contract_test.go`）。
- [x] Classify breaking changes and compatibility promises（envelope 契约与 Python 版完全兼容，客户端无感切换）。
- [x] Update user and configuration documentation（README/README_EN 已重写为 Go 版）。

## Development and review

- [x] Project metadata and one canonical version source report `1.0.0-fast`（go.mod module + server name）。
- [x] No embedded credentials, debug artifacts or unreviewed generated files ship（源码扫描无明文密钥/口令）。
- [x] Code review covers command construction, paths, host identity, authentication, timeouts, concurrency, logging and secret redaction（golangci-lint + review 包测试 + audit 脱敏测试）。
- [x] Four-mode review decisions bind to the normalized operation actually executed（review.Result.PlanID + envelope.review.plan_id）。
- [x] Defense-in-depth: injection/dangerous patterns enforced in all modes incl. off（`review.ValidateCommand` + bypass 测试）。

## Test and security gates

- [x] Unit and regression tests exist（92 tests across 5 packages）。
- [x] Focused MCP contract tests exist（`contract_test.go`：tools/list 精确 8 工具 + schema enum + envelope 字段契约）。
- [x] Review-mode tests cover off/whitelist/manual/smart decisions, including bypass attempts and fallback behavior（`bypass_test.go` 27 用例 + `review_test.go`）。
- [x] SFTP atomic transfer tests（`sftp_test.go`：上传/下载原子性、覆盖、校验和、临时文件清理）。
- [x] Host-key strict policy tests（`hostkey_test.go`：known_hosts 解析、接受/拒绝/不匹配、端口形式）。
- [x] Race detector clean（`go test -race` 无竞态）。
- [x] Static analysis clean（`golangci-lint` 零告警）。
- [x] Dependency, secret and vulnerability scans have no unaccepted findings（`govulncheck`；Go 1.26.4 标准库 TLS 漏洞 → 升级 1.26.5）。
- [ ] Integration tests cover supported local/remote OS combinations, authentication methods, file operations, failures, timeout and cancellation（WSL2 真实 E2E：hostname/SFTP/超时/故障注入已验证；Windows 本地 + Linux 远端组合待补充）。

## Package and operations

- [ ] Build artifacts from a clean checkout; install and MCP-smoke-test those exact artifacts（`go build` 单二进制 10.6MB，待干净 checkout 验证）。
- [ ] Record artifact hashes, dependency lock (go.sum), source commit and CI run URL。
- [ ] Define configuration migration, backup, rollback, log retention, monitoring and incident ownership（审计日志 JSONL 保留于 ~/.ssh/mcp-ssh.log）。
- [ ] Validate installation and startup instructions on every supported client platform（Windows/Linux 已测；macOS 不支持）。
- [ ] Prepare release notes with known limitations and security-relevant changes（CHANGELOG 1.0.0-fast）。

## Go / no-go and release

- [ ] Product, development, test/security and operations owners explicitly approve go-live。
- [ ] Create the final annotated tag only from the accepted commit, then publish matching artifacts and notes。
- [ ] Run post-release smoke tests, monitor failures and exercise the documented rollback trigger if needed。
