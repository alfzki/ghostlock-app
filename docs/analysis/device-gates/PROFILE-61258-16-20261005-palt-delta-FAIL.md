# PROFILE-61258-16-20261005 — P-alt per-delta probe（三增量只读探针）：零区分度，`NO_DELTA` 回退成立（FAIL）

- **日期**：2026-10-05（单轮主跑）
- **设备**：`10AFAL1TD7002HB`（vivo V2514）
- **内核**：`6.12.58-android16-6-gff10eaa8f8a4-ab15575650-4k`
- **构建**：`e032c88` + 未提交工作树（T3–T14 + P-alt），二进制 sha256 `73608fb71a7d0e5ec3ebfabd72f620a7b819d07ccefd688e7ae301c10c00747d`（短 `73608fb71a7d0e5e`，已核对设备侧一致）
- **profile**：GLK1 v2，2226 B，sha256 `1b0c9200c43f70b6d6394061c4ebbdc96868bbb1a8b541d19bf8a76650785a03`（自门禁 -09 未变）
- **改动**（相对门禁 -15 的 `022704c1`，单变量即探针）：每轮对候选增量 `{0x100, 0x108, 0x122}` 各做一次只读 `epoll_wait(...,0)`（`fake_rdllink = epitem_base + 0x18 | delta`，rdllink 相对构造），记 `EPROBE_DELTA delta= n= fds=`；取唯一扰动增量，无区分则保持默认 `0x108` + 记 `NO_DELTA`；诊断专用，不碰内核对象、不改判据。
- **原始证据**：`logs/gate-20261005-101053-palt-delta/`（`native.log` 369118 B + 两 sha + commit）
- **设计文档**：`docs/development/61258-fdgraph-real-inject-plan.md` §3 T6/OQ-A（probe-first，`rdllink` 非 `fllink`、`LIST_POISON2` 更正）

## 门禁前置（`tools/gate_preflight.py` 6/6 PASS，冷启动 8.66 s）

设备唯一、KernelSU 未加载、`uname -r` 精确匹配、`RLIMIT_NOFILE` 32768、锁屏状态仅记录。插机时 uptime 42747 s，reboot 后 8.66 s 通过。

## 结果

| 项 | 值 |
|---|---|
| 进程终态 | exit 1（自主）✅ |
| `EPROBE_DELTA`（每轮 ×3） | `delta=0x100 n=0` / `delta=0x108 n=0` / `delta=0x122 n=0` —— **三增量零区分度** |
| `KNOWN_PAGE` | `base=00000073800ee000 candidate=00000073800ee108 delta=0x108`（回退默认）✅ |
| `NO_DELTA` | 出现 ✅（回退路径按设计触发） |
| `RACE round=9 delay_us=64 chain_hit=0 bit4=0 marker_changed=0` | ✅ |
| `RACE_SUMMARY tries=10 pipe_fill_hits=2400 chain_hits=0 bit4_hits=0` | 诚实零值 ✅ |
| `PIPE_OBSERVED` | 4480 行，全 `ESPIPE` ✅ |
| `route_done` ×28 / `threads joined` | ✅ |
| W1 全程 | 15/15 跑完 → `Write 1 failed`，`enforce state=0` |
| SELinux / panic | Enforcing（预期内）/ **无**（8.66 s → 47.95 s 连续） |

**判定：FAIL**（W1 未完成）。但本门禁回答了 P-alt 的问题：只读探针在三增量下输出全同（`n=0`），无法选择。深层含义：该探针未改变任何内核可见状态（三次迭代观测的是同一张未投毒图），按构造就不可区分——不是增量的问题，是探针的问题。真正的区分信号只能来自**把候选值种进去再看遍历反应**（逐增量硬编码各跑一轮门禁，比 `chain` 行为），或重审构造边。

## 门槛

- host tests 23/23 / NDK 零警告 / lint-tidy 0 findings（worker 内门禁）
- `cmp_disasm` 真基线：`LAYOUT-SHIFT`-only（worker 内门禁；0 `SHAPE-DIFF`）
- 冷启动 + `tools/gate_preflight.py`：6/6
- 设备侧二进制 sha 与本地一致（`73608fb71a7d0e5e`）

## 下一步

二选一（均需独立批次）：(a) 逐增量硬编码门禁 ×3（每轮只改默认增量常数，比 `chain_hit`/`marker_changed` 行为——贵但决定性）；(b) 重审毒化载体（`rdllink` 相对构造是否落到内核实际遍历的边）。在此之前不得标 supported。
