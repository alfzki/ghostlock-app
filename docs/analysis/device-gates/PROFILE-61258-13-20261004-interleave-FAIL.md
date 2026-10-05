# PROFILE-61258-13-20261004 — spray 移位（small→spray→expand）：顺序如设计，投递仍 `chain_hits=0`（FAIL）

- **日期**：2026-10-04
- **设备**：`10AFAL1TD7002HB`（vivo V2514）
- **内核**：`6.12.58-android16-6-gff10eaa8f8a4-ab15575650-4k`
- **构建**：`e032c88` + 未提交工作树（spray 调用点移位一批），二进制 sha256 `86969d35893a8c4861803ba46a1ca61fe216ec28736cf3d56b90ecabadda94be`（短 `86969d35893a8c48`，已核对设备侧一致）
- **profile**：GLK1 v2，2226 B，sha256 `1b0c9200c43f70b6d6394061c4ebbdc96868bbb1a8b541d19bf8a76650785a03`（自门禁 -09 未变）
- **改动**（相对门禁 -12 的 `4b3f8719`，单变量即调用点顺序）：`spray_reclaim_mass(150)` 调用从 `GRAPH_READY` 后移到 `reclaim_small` 完成之后、`reclaim_expand` 之前；零新增 syscall、零新成员、零测试变更（逻辑未动，纯移位）。
- **原始证据**：`logs/gate-20261004-interleave/`（`native.log` 69913 B、`binary.sha256`、`profile.sha256`、`build_commit.txt`）

## 门禁前置（`tools/gate_preflight.py`，全部 PASS）

| 检查 | 结果 | 实测值 |
|---|---|---|
| 设备唯一 | PASS | `10AFAL1TD7002HB` |
| 冷启动 | PASS | uptime 35290 ms（< 120000 ms） |
| KernelSU 未加载 | PASS | 无模块、无 marker |
| `uname -r` 精确匹配 | PASS | `6.12.58-android16-6-gff10eaa8f8a4-ab15575650-4k` |
| `RLIMIT_NOFILE` 余量 | PASS | soft=32768 hard=32768，需 ≥24736 |
| 锁屏状态（仅记录） | 记录 | Asleep + locked（与既往门禁一致，非判定项） |

## 结果

| 项 | 值 |
|---|---|
| 执行顺序 | **每轮均为 `reclaim_small` → `spray_children 150/150` → `reclaim_expand`** ✅（行号单调：small 行 < spray 行 < expand 行，14/14 轮） |
| 进程终态 | 自主退出 exit=1 ✅ |
| `GRAPH_READY` / `PIPE_TARGET` / `cmd_gate` / `payload_writes` / `enforce state=0` / `decoy_unlink rc=0` | 与门禁 -12 同形，全通 ✅ |
| `RACE_SUMMARY` | `chain_hits=0 bit4_hits=0 delivery=not-implemented`（诚实零值） |
| `route_done` + `threads joined` | 14/14 ✅ |
| W1 全程 | 15/15 attempts 跑完 → `Write 1 failed` |
| SELinux | Enforcing（预期内） |
| panic | **无**（跑后 uptime 连续 29 s → 109 s，`sys.boot.reason=reboot,shell`） |

**判定：FAIL**（W1 未完成）。但 OQ2 的“位置”一半已回答：spray 落在 small/expand 之间可稳定执行、无 panic、无挂起、无短写。

## 说明

1. **OQ2 的诚实结论**：在成功率为 0 的前提下，A/B  placement 对比是不可分辨的——两版日志除顺序行外逐行同形。本门禁的价值是**安全性**（新顺序不引入崩溃/挂起/泄漏）而非有效性；有效性仍待真实 inject。
2. **`cmp_disasm` 附带结论**：本批真基线对比回到 6× `OPERAND-DIFF`（计数逐项一致）+ 零分支/调用变化；门禁 -12 的 erratum `SHAPE-DIFF` 未复现——进一步佐证其为布局噪声而非逻辑漂移。
3. 单次无 panic 不构成因果结论（`KERNEL-PANIC-01`）。

## 门槛

- host tests 21 suites / NDK 零警告 / lint-tidy 0 findings（本批无逻辑变更，测试集不变即覆盖）
- `cmp_disasm` 见上（6× `OPERAND-DIFF` + 2× `STALE`）
- 冷启动 + `tools/gate_preflight.py`：PREFLIGHT PASS 6/6
- 设备侧二进制 sha 与本地一致（`86969d35893a8c48`）

## 下一步

顺序变量已穷尽其信息量（两种顺序同样安全、同样零信号）。下一次 L 级工作必须是 **fork redirect（OQ3-B）或真实 inject**，二者都不再是移位可及——需独立设计与门禁。在此之前不得标 supported。
