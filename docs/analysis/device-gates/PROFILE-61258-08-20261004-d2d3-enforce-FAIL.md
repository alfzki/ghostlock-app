# PROFILE-61258-08-20261004 — D2 门控 + D3 enforce 验收通路：全链路诚实运行，投递仍 `chain_hits=0`（FAIL）

- **日期**：2026-10-04
- **设备**：`10AFAL1TD7002HB`（vivo V2514）
- **内核**：`6.12.58-android16-6-gff10eaa8f8a4-ab15575650-4k`
- **构建**：`99a326d` + 未提交工作树（D1 表 + D2 门控 + D3 enforce 验收），二进制 sha256 `5210e4e8107da7bc868effd8b0f1e3a38c7129c450d5f25b07cfde0ff9f44155`（短 `5210e4e8107da7bc`，已核对设备侧一致）
- **profile**：GLK1 v2，2226 B，sha256 `550d1b0f4057a404f84e5233d12e96d14926d879f1b400b7c35ddd0258e76d4b`（与批次 A 同值，本批未改 profile）
- **改动**（相对门禁 -07 的 `ce448666`）：
  1. D1：建管循环内逐槽 `reclaim_small`（参考 §2.10 环形），expand 仍在环后；staging `+0xF80` 起 16 项 `{page+0x100+i*0x800, 0}`（`page` 取自本轮真实 `heap.current.base`）+ `PIPE_TARGET` 日志。
  2. D2：私有 `pipe2` 对自环 `'W'` 命令门（避开 consumer 线程竞态），`cmd_gate` 日志；失败关管释表回 `RETRYABLE`。
  3. D3：`RACE_SUMMARY` 后读 `/sys/fs/selinux/enforce`，`enforce state=` 日志；`!= '1'` 才置 `ROUTE_OK`（本次恒为 0，零行为变化）。
- **原始证据**：`logs/gate-20261004-d2d3/`（`native.log` 67638 B、`binary.sha256`、`profile.sha256`、`build_commit.txt`）

## 门禁前置（`tools/gate_preflight.py`，全部 PASS）

| 检查 | 结果 | 实测值 |
|---|---|---|
| 设备唯一 | PASS | `10AFAL1TD7002HB` |
| 冷启动 | PASS | uptime 31770 ms（< 120000 ms） |
| KernelSU 未加载 | PASS | 无模块、无 marker |
| `uname -r` 精确匹配 | PASS | `6.12.58-android16-6-gff10eaa8f8a4-ab15575650-4k` |
| `RLIMIT_NOFILE` 余量 | PASS | soft=32768 hard=32768，需 ≥24736 |
| 锁屏状态（仅记录） | 记录 | Asleep + locked（与既往门禁一致，非判定项） |

## 结果

| 项 | 值 |
|---|---|
| 进程终态 | **自主退出 exit=1** ✅（无挂起，hang 修复保持） |
| `GRAPH_READY` | width=96 fanout=256 edges=24576 ✅（ELOOP 未复发） |
| `PIPE_TARGET` | 每轮真实内核页（如 `ffffff829aa10000`，逐轮变化）`fake_count=16 object_size=0x800 slot=10 flags_off=0x18` ✅ |
| `cmd_gate cmd=W ok=1` | **14/14** ✅（D2 门控通路成立） |
| `payload_writes ok=240` | 全轮 ✅ |
| `enforce state=0` | **14/14** ✅（D3 通路成立；Enforcing 下诚实为 0） |
| `RACE_SUMMARY` | `chain_hits=0 bit4_hits=0 delivery=not-implemented`（诚实零值） |
| `route_done` + `threads joined` | **14/14** ✅ |
| W1 全程 | 15/15 attempts 跑完 → `Write 1 failed` |
| SELinux | Enforcing（W1 未翻，预期内） |
| panic | **无**（跑后 uptime 连续 28 s → 76 s，`sys.boot.reason=reboot,shell`） |

**判定：FAIL**（W1 未完成）。但 D1/D2/D3 三个通路目标全部达成。

## 说明

1. **14 vs 15**：15 attempts 中 14 次进入 route（1 次在堆喷洒阶段即重试），`threads joined` ×14 与建图次数一致。
2. **`SHAPE-DIFF` 注解**（`consumer_thread`，真基线 `99a326d` 干净树 vs 本批）：179 条中仅第 [147] 条由 `ldr w9, [x9, #0x7e0]` 变为跳往 `__CortexA53843419_69004` 存根；存根本体仅两条（`ldr w9, [x9, #0xe80]` + 跳回 fall-through `0x69008`），语义与原加载完全一致，分支/调用/助记符其余零变化。这是新日志串撑大 rodata 导致某 `adrp` 越过 4K 页边界而触发的编译器 Cortex-A53 erratum 843419 外提，与 race 逻辑无关（该函数源码未动）。记为已注解 benign，不阻塞。其余 5 函数仍为 `OPERAND-DIFF`（计数一致，纯偏移平移）。
3. **`enforce state=0` 的含义**：D3 通路可读可判（OQ1 已证 shell 可读），本次恒 0 是因为尚无真实写入翻转 SELinux——判据在线，信号未到。
4. **单次无 panic 不构成因果结论**（`KERNEL-PANIC-01`）。

## 门槛

- host tests 21 suites（含表/门控/enforce 共 29 个新向量）/ NDK 零警告 / lint-tidy 0 findings
- `cmp_disasm` 真基线：5× `OPERAND-DIFF`（计数一致）+ 1× 已注解 benign `SHAPE-DIFF`（见上）+ 2× `STALE`
- 冷启动 + `tools/gate_preflight.py`：PREFLIGHT PASS 6/6
- 设备侧二进制 sha 与本地一致（`5210e4e8107da7bc`）

## 下一步

真正的 slot 选取 + `RECLAIM_HIT` + 内核读回 + `marker_changed`（scoping §2.18.2）仍是唯一缺口；`pread64` 不得用于管道/epoll（OQ1：`ESPIPE`）。下一次门禁前置仍是冷启动 + 全套 preflight。
