# PROFILE-61258-15-20261004 — real-inject 基座（RLIMIT + 24.5k 图 + 480 管 + probe/GENMARK0 + merge-payload + 触发链）：全程自主回收，`chain` 诚实零值（FAIL）

- **日期**：2026-10-04（单轮主跑）
- **设备**：`10AFAL1TD7002HB`（vivo V2514）
- **内核**：`6.12.58-android16-6-gff10eaa8f8a4-ab15575650-4k`
- **构建**：`e032c88` + 未提交工作树（T3–T14 整批：RLIMIT、`BulkFdArrayOwner`、480 管分离、probe/GENMARK0/`fake_fllink`、merge-payload、W 门、240-write、`pread64`、重试环、decoy、fork、enforce 验收、lifecycle），二进制 sha256 `022704c103ebffaa13cf660ffcad29e62ec58e8685b502fa89717a61690c20cd`（短 `022704c103ebffaa`，已核对设备侧一致）
- **profile**：GLK1 v2，2226 B，sha256 `1b0c9200c43f70b6d6394061c4ebbdc96868bbb1a8b541d19bf8a76650785a03`（自门禁 -09 未变）
- **改动**（相对门禁 -14 的 `9aa1a70a`，多变量但均为投递基座件，行为增量逐批已过 host/NDK/lint 门槛）：`FD_LIMIT_INITIAL` 相对式抬限；24,576 epoll 图迁入 RAII 批量持有；240 管对拆分为 reclaim/drain 双环（各 240，两张 `0x780` 表，空槽 `-1`，reclaim 双级 `F_SETPIPE_SZ` + `F_GETPIPE_SZ` 回读）；只读 `epoll_wait` 遍历 probe（诊断）；GENMARK0 68 份 + 参数化 `fake_fllink(base,delta)`（默认 `base|0x108`，不断言）；merge-payload（slot+`0x166` 窗内 `flags@0x18` bit4 + 配对 `ops`/`ops->release`，GENMARK0 精确避让）；`PIPE_OBSERVED` 按槽 `pread64`（`ESPIPE` 诚实记零命中）；其余（W 门/重试判据/decoy 序/fork 拓扑/enforce 验收/清理）逐行沿用 -14。
- **原始证据**：`logs/gate-20261004-221758-inject-base/`（`native.log` 319688 B + 两 sha + commit）
- **设计文档**：`docs/development/61258-fdgraph-real-inject-plan.md` §3 T3–T14（用户已评审：480 分离 + probe-first）

## 门禁前置（`tools/gate_preflight.py` 6/6 PASS，冷启动 8.8 s）

设备唯一、KernelSU 未加载、`uname -r` 精确匹配、`RLIMIT_NOFILE` 32768（图需 +24736）、锁屏状态仅记录。首轮 reboot 后曾以 126990 ms 错过冷窗 7 s，重 reboot 后 8850 ms 通过。

## 结果

| 项 | 值 |
|---|---|
| 进程终态 | exit 1（自主）✅ |
| `FD_LIMIT_INITIAL cur=32768 max=32768 graph_only=24736` | 首轮即现 ✅ |
| `GRAPH_READY width=96 fanout=256 edges=24576` | ✅ |
| `KNOWN_PAGE base=00000076c1e9d000 candidate=00000076c1e9d108 delta=0x108` | ✅（默认档，probe 未切档） |
| `PIPE_TARGET page=ffffff82d56f0000 fake_count=16 object_size=0x800 slot=10 flags_off=0x18` | ✅ |
| `cmd_gate cmd=W ok=1` / `payload_writes ok=240 total=240 payload=8` | ✅ |
| `redirect mode=zero_byte_redirect needs_bit4=0` | ✅ |
| `PIPE_OBSERVED` | 3840 行，全 `ESPIPE`（诚实零命中）✅ |
| `RACE round=9 delay_us=64 chain_hit=0 bit4=0 marker_changed=0 generation=304b52414d4e4547` | ✅ |
| `RACE_SUMMARY tries=10 pipe_fill_hits=2400 chain_hits=0 bit4_hits=0 delivery=not-implemented` | 诚实零值 ✅ |
| `route_done` ×24 / `threads joined` ×12 | ✅ |
| W1 全程 | 15/15 跑完 → `Write 1 failed`，`enforce state=0` |
| SELinux / panic | Enforcing（预期内）/ **无**（8.8 s → 75.38 s 连续，`reboot,shell`） |

**判定：FAIL**（W1 未完成，符合预期——probe 尚未选出毒化增量，内核侧无 inject 信号）。本门禁价值 = 基座安全：480 分离 + probe + lifecycle 在真机上无崩溃、无挂起、无短写、无 fork/超时事件，自主退出。

## 门槛

- host tests 24 suites / NDK 零警告 / lint-tidy 0 findings / app 单测 SUCCESS / export UP-TO-DATE
- `cmp_disasm` 真基线：6× `OPERAND-DIFF`（计数逐项一致，一致 `+0xA0` 级偏移）+ 零分支/调用变化 → 已注解 `LAYOUT-SHIFT` 类；0 `SHAPE-DIFF`
- 冷启动 + `tools/gate_preflight.py`：6/6
- 设备侧二进制 sha 与本地一致（`022704c103ebffaa`）

## 下一步

跑 `epoll_wait` probe 读数选出 `0x100`/`0x108`/`0x122` 毒化增量（下一独立批次），再谈 `chain`。在此之前不得标 supported。
