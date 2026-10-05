# PROFILE-61258-12-20261004 — `decoy_unlink`（`EPOLL_CTL_DEL`，`event=NULL`）：14/14 成功，投递仍 `chain_hits=0`（FAIL）

- **日期**：2026-10-04
- **设备**：`10AFAL1TD7002HB`（vivo V2514）
- **内核**：`6.12.58-android16-6-gff10eaa8f8a4-ab15575650-4k`
- **构建**：`e032c88` + 未提交工作树（decoy 一批），二进制 sha256 `4b3f871912d68c230fb8ecb1a12c1264a5b3c0a68077afb5fe1d71177e17623f`（短 `4b3f871912d68c23`，已核对设备侧一致）
- **profile**：GLK1 v2，2226 B，sha256 `1b0c9200c43f70b6d6394061c4ebbdc96868bbb1a8b541d19bf8a76650785a03`（自门禁 -09 未变）
- **改动**（相对门禁 -11 的 `c6c4d571`，单变量即 DEL 通路）：RACE 环结束后、管道回收前，对 star 图第 0 组（`child = epoll_fds[3]` 监视 `base = epoll_fds[2]`）执行 `EPOLL_CTL_DEL`（`event=NULL`），记 `decoy_unlink child=%d base=%d rc=%d errno=%d`；`rc != 0` 只记不判。`close_after_trigger` 天然成立（epoll fds 只在 `destroy()` 才关）。
- **原始证据**：`logs/gate-20261004-decoy/`（`native.log` 71885 B、`binary.sha256`、`profile.sha256`、`build_commit.txt`）
- **设计文档**：`docs/development/61258-fdgraph-trigger-plan.md`（L 级，fork 递延记于 OQ3-B）

## 门禁前置（`tools/gate_preflight.py`，全部 PASS）

| 检查 | 结果 | 实测值 |
|---|---|---|
| 设备唯一 | PASS | `10AFAL1TD7002HB` |
| 冷启动 | PASS | uptime 34760 ms（< 120000 ms） |
| KernelSU 未加载 | PASS | 无模块、无 marker |
| `uname -r` 精确匹配 | PASS | `6.12.58-android16-6-gff10eaa8f8a4-ab15575650-4k` |
| `RLIMIT_NOFILE` 余量 | PASS | soft=32768 hard=32768，需 ≥24736 |
| 锁屏状态（仅记录） | 记录 | Asleep + locked（与既往门禁一致，非判定项） |

## 结果

| 项 | 值 |
|---|---|
| `decoy_unlink child=9 base=8 rc=0 errno=0` | **14/14** ✅（DEL 通路成立；零非零 `rc`） |
| 进程终态 | 自主退出 exit=1 ✅ |
| `GRAPH_READY` / `spray_children 150/150` / `PIPE_TARGET` / `cmd_gate` / `payload_writes` / `enforce state=0` | 与门禁 -11 同形，全通 ✅ |
| `RACE_SUMMARY` | `chain_hits=0 bit4_hits=0 delivery=not-implemented`（诚实零值） |
| `route_done` + `threads joined` | 14/14 ✅ |
| W1 全程 | 15/15 attempts 跑完 → `Write 1 failed` |
| SELinux | Enforcing（预期内） |
| panic | **无**（跑后 uptime 连续 28 s → 117 s，`sys.boot.reason=reboot,shell`） |

**判定：FAIL**（W1 未完成）。DEL 通路目标达成。

## 说明

1. **14 vs 15**：15 attempts 中 14 次进入 route（1 次在堆喷洒阶段即重试），各计数器 ×14 一致。
2. **`rc != 0` 弱断言的正确性**：本次 14/14 为 `rc=0`；若未来某轮出现非零（如重复 DEL 的 `ENOENT`），按设计只记不判——“无毒可摘”不是故障。
3. **`cmp_disasm` 注解**（真基线 `99a326d` 干净树 vs 本批）：5× `OPERAND-DIFF`（计数逐项一致）+ 1× 已注解 benign `SHAPE-DIFF`：`run_main_route_threads` 179 条中仅 2 条由 `ldr wN, [x22, #0xbb0]` 变为 `ldr wN, [x22]`；`nm` 证实两边读的是**同一变量**（`g_exploit_session+0x670`，结构体尺寸一致 `0x6d0`），只是 rodata/BSS 增长把该字段推到了 `adrp` 页基址上，偏移操作数消失——零分支/调用/助记符变化。基线侧的 libunwind 注解是 objdump 就近符号噪声。
4. 单次无 panic 不构成因果结论（`KERNEL-PANIC-01`）。

## 门槛

- host tests 21 suites（含 decoy ADD→DEL→重 DEL 向量）/ NDK 零警告 / lint-tidy 0 findings
- `cmp_disasm` 见上（5× `OPERAND-DIFF` + 1× 已注解 benign `SHAPE-DIFF` + 2× `STALE`）
- 冷启动 + `tools/gate_preflight.py`：PREFLIGHT PASS 6/6
- 设备侧二进制 sha 与本地一致（`4b3f871912d68c23`）

## 下一步

trigger 环只剩 fork redirect（OQ3-B，`ChildProcess` 基础设施就绪）；真正的 `chain` 仍待喷洒页→释放环重占（OQ2）与触发变体。在此之前不得标 supported。
