# PROFILE-61258-11-20261004 — buddy 读探针：`/proc/buddyinfo` shell 不可读，通路证伪（FAIL）

- **日期**：2026-10-04
- **设备**：`10AFAL1TD7002HB`（vivo V2514）
- **内核**：`6.12.58-android16-6-gff10eaa8f8a4-ab15575650-4k`
- **构建**：`e032c88` + 未提交工作树（buddy 探针一批），二进制 sha256 `c6c4d571e0c93cec9a9b82c9ee546238facaf75c4f6f421e3877a6f9ebfcc81f`（短 `c6c4d571e0c93cec`，已核对设备侧一致）
- **profile**：GLK1 v2，2226 B，sha256 `1b0c9200c43f70b6d6394061c4ebbdc96868bbb1a8b541d19bf8a76650785a03`（自门禁 -09 未变）
- **改动**（相对门禁 -10 的 `929ccf80`，唯一增量即只读探针）：`GRAPH_READY` 后取 buddy 快照 A，expand 后取 B 并记 delta；`read_buddy_free_total()` 打不开文件即回 `-1` 并记 `unavailable` 后继续。
- **原始证据**：`logs/gate-20261004-buddy/`（`native.log` 75064 B、`binary.sha256`、`profile.sha256`、`build_commit.txt`）
- **设计文档**：`docs/development/61258-fdgraph-readback-plan.md`（红线：staging 自读回不得作为信号）

## 门禁前置（`tools/gate_preflight.py`，全部 PASS）

| 检查 | 结果 | 实测值 |
|---|---|---|
| 设备唯一 | PASS | `10AFAL1TD7002HB` |
| 冷启动 | PASS | uptime 55400 ms（< 120000 ms） |
| KernelSU 未加载 | PASS | 无模块、无 marker |
| `uname -r` 精确匹配 | PASS | `6.12.58-android16-6-gff10eaa8f8a4-ab15575650-4k` |
| `RLIMIT_NOFILE` 余量 | PASS | soft=32768 hard=32768，需 ≥24736 |
| 锁屏状态（仅记录） | 记录 | Asleep + locked（与既往门禁一致，非判定项） |

## 结果

| 项 | 值 |
|---|---|
| buddy 快照 | **`buddy unavailable before=-1 after=-1` ×15** —— `/proc/buddyinfo` 在 shell 下 `open` 失败，E1 观测通道在本机不存在 |
| 优雅降级 | ✅ 探针失败零影响：其后 `spray_children 150/150`、`GRAPH_READY`、`PIPE_TARGET`、`cmd_gate`、`payload_writes`、`enforce` 全通 |
| 进程终态 | 自主退出 exit=1 ✅ |
| `route_done` + `threads joined` | 15/15 ✅ |
| `RACE_SUMMARY` | `chain_hits=0 bit4_hits=0`（诚实零值） |
| W1 全程 | 15/15 attempts 跑完 → `Write 1 failed` |
| SELinux | Enforcing（预期内） |
| panic | **无**（跑后 uptime 连续 28 s → 136 s，`sys.boot.reason=reboot,shell`） |

**判定：FAIL**（W1 未完成，且 E1 无反馈）。buddy 通道证伪：不可读即无信号，不重试该方向。

## 说明

1. **否定性结论同样归档**：E1 的价值就是排除一个方向。`/proc` 分配器计数在本机 shell 上下文不可观测——此路不通，后续不再投入。
2. **per-round 内核信号问题至此结案**：staging 自读回是自证预言（红线已立），管道/epoll 上 `pread` 必 `ESPIPE`（OQ1），buddy/slab 类计数不可读（本门禁）。在 inject 落地前，不存在诚实可用的 round 内信号；验收维持 enforce 文件，诊断维持现有日志口径。
3. **剩余缺口唯一且明确**：喷洒页→释放环重占时序（OQ2）与触发变体——即让内核真正走进投毒链的那一下。这是下一个独立 L 级设计，不得与本批观测代码混批。
4. 单次无 panic 不构成因果结论（`KERNEL-PANIC-01`）。

## 门槛

- host tests 21 suites（含 buddy 罐装/缺失/空文件三向量）/ NDK 零警告 / lint-tidy 0 findings
- `cmp_disasm` 真基线：6× `OPERAND-DIFF`（计数逐项一致，纯偏移平移）+ 零分支/调用变化 → 已注解 `LAYOUT-SHIFT` 类
- 冷启动 + `tools/gate_preflight.py`：PREFLIGHT PASS 6/6
- 设备侧二进制 sha 与本地一致（`c6c4d571e0c93cec`）

## 下一步

关闭“找信号”方向；下一批只做“造着陆”：OQ2 交错 + 触发变体，单变量、冷启动门禁。不在此之前标 supported。
