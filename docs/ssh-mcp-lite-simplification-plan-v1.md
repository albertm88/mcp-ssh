# ssh-mcp lite 分支简化 Plan（v1）

## PLAN 元信息
- **Plan 名称**: ssh-mcp-lite-simplification-v1
- **分支**: `lite`
- **启动时间**: 2026-08-10
- **类型**: 重构 / 功能精简
- **目标形态**: 合并文件类工具 + 删除 scan，保持剩余功能完整

## 一、背景与目标
`lite` 分支当前与 `main` 仅差一个 SECURITY.md 版本号，简化尚未开始。
server.py 单文件 2216 行、15 个 MCP 工具、779 行 review 引擎。本次在 lite 分支做结构性精简：

1. **合并文件类工具**：`ssh_list_dir` / `ssh_stat_file` / `ssh_mkdir` / `ssh_remove` → 单一 `ssh_filesystem`（action 参数区分）。
2. **删除 `ssh_scan`**：网络扫描能力在 lite 定位中移除。
3. **清理死代码**：重复 `main()`、`review_command`、`envelope_to_text`/`to_mcp_text`、未使用常量。
4. **合并重复辅助函数**：`_sftp_bounded_walk`↔`_local_bounded_walk`、连接错误映射、敏感路径/遍历守卫。

**保持功能完整**：`ssh_exec`、`ssh_upload`、`ssh_download`、`ssh_exec_batch`、`ssh_get_review_mode`、`ssh_set_review_mode`、`ssh_get_audit_logs`、`ssh_list_hosts` 全部保留且行为不变。

## 二、变更范围

### 工具变更
| 现状 | 变更后 |
|------|--------|
| `ssh_scan` | 删除 |
| `ssh_list_dir` | 并入 `ssh_filesystem`(action="list") |
| `ssh_stat_file` | 并入 `ssh_filesystem`(action="stat") |
| `ssh_mkdir` | 并入 `ssh_filesystem`(action="mkdir") |
| `ssh_remove` | 并入 `ssh_filesystem`(action="remove") |
| 其余 10 个工具 | 保留，行为不变 |

**新 `ssh_filesystem` 签名**（规划）：
```python
def ssh_filesystem(host, action, remote_path, parents=True,
                   recursive=False, show_hidden=False, timeout=10) -> dict
```
`action` ∈ `{"list","stat","mkdir","remove"}`；每种 action 复用原工具的安全守卫与 review 逻辑。

### 文件清单
| 文件 | 操作 | 说明 |
|------|------|------|
| `server.py` | 修改 | 合并/删除工具、清理死代码、合并辅助函数 |
| `review.py` | 修改 | 删除死代码 `review_command` |
| `results.py` | 修改 | 删除死代码 `envelope_to_text`/`to_mcp_text`、未用常量 |
| `docs/architecture.md` | 修改 | 工具数量 14→新值、工具名表 |
| `docs/requirements-1.0.md` | 修改 | 工具映射表 |
| `README.md` | 修改 | 工具一览、文件树 |
| `tests/test_delivery_contract.py` | 修改 | 工具清单、scan 相关测试 |
| `tests/test_review_fixes.py` | 修改 | mkdir 引用改 `ssh_filesystem` |
| `tests/test_sftp_control.py` | 保持 | 若 walker 合并则微调 |

## 三、Tasks
- [ ] T1: 合并 4 个文件工具为 `ssh_filesystem`（server.py）
- [ ] T2: 删除 `ssh_scan` 及 `_scan_subnet`、`_MAX_SCAN_ADDRESSES`（如无其他引用）
- [ ] T3: 清理死代码（main 重复、review_command、envelope_to_text/to_mcp_text、未用常量）
- [ ] T4: 合并重复辅助函数（bounded walk、连接错误映射、守卫块）
- [ ] T5: 更新测试（test_delivery_contract、test_review_fixes）
- [ ] T6: 更新文档（architecture.md、requirements-1.0.md、README.md）
- [ ] T7: 运行测试套件并验证

## 四、验收标准
- [ ] `pytest` 全绿（含更新后测试）
- [ ] MCP tools 数量从 15 变为 11（15 − scan − 4 文件 + 1 filesystem）
- [ ] 保留工具的行为与返回 envelope 契约不变
- [ ] 无死代码残留（grep 确认）
- [ ] 文档中的工具名/数量与实际实现一致

## 五、关联文档
- `docs/architecture.md`
- `docs/requirements-1.0.md`
- `README.md`
- `docs/release-checklist.md`
