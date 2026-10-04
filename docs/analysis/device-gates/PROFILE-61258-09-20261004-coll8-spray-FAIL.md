# PROFILE-61258-09-20261004 — kernelsnitch `collisions` 4→8（对齐参考 `kernelsnitch_setup`）：扫描通过、无 panic（FAIL）

- **日期**：2026-10-04
- **设备**：`10AFAL1TD7002HB`（vivo V2514）
- **内核**：`6.12.58-android16-6-gff10eaa8f8a4-ab15575650-4k`
- **构建**：native 二进制未变（sha256 `5210e4e8107da7bc868effd8b0f1e3a38c7129c450d5f25b07cfde0ff9f44155`，设备侧一致）
- **改动**（相对门禁 -08，仅 profile）：`kernelsnitch.collisions` `4`→`8`
  （对齐 `annotated.c` `kernelsnitch_setup` 行的 `collisions=8`），GLK1 随之变为
  sha256 `1b0c9200c43f70b6d6394061c4ebbdc96868bbb1a8b541d19bf8a76650785a03`，
  `native-doc-golden.sha256` 同步；app 80 tests 全过（含等价性与全字段校验）
- **原始证据**：`logs/gate-20261004-coll8/`（`native.log`、`binary.sha256`、`profile.sha256`、`build_commit.txt`）

## 门禁前置（`tools/gate_preflight.py`，全部 PASS）

| 检查 | 结果 | 实测值 |
|---|---|---|
| 设备唯一 | PASS | `10AFAL1TD7002HB` |
| 冷启动 | PASS | uptime 106430 ms（< 120000 ms；注：本次为跑后补测，同一连续启动内，`bootreason` 无变化，可归因） |
| KernelSU 未加载 | PASS | 无模块、无 marker |
| `uname -r` 精确匹配 | PASS | `6.12.58-android16-6-gff10eaa8f8a4-ab15575650-4k` |
| `RLIMIT_NOFILE` 余量 | PASS | soft=32768 hard=32768，需 ≥24736 |
| 锁屏状态（仅记录） | 记录 | Asleep + locked（与既往门禁一致，非判定项） |

## 结果

| 项 | 值 |
|---|---|
| 碰撞扫描 | **31/31 `futex collisions found`** ✅（阈值随 collisions 自适应：`13/7`、`11/7`、`7/7 at 31%`；单次约 870–910 ms，相对 collisions=4 的 ~800 ms 无实质增长） |
| 进程终态 | 自主退出 exit=1 ✅ |
| `GRAPH_READY` / `PIPE_TARGET` / `cmd_gate` / `payload_writes` / `enforce` / `route_done`+join | 与门禁 -08 同形，全通 ✅ |
| `RACE_SUMMARY` | `chain_hits=0 bit4_hits=0`（诚实零值；喷洒面尚未动） |
| W1 全程 | 15/15 attempts 跑完 → `Write 1 failed` |
| SELinux | Enforcing（预期内） |
| panic | **无**（跑后 uptime 连续 28 s → 92 s，`sys.boot.reason=reboot,shell`） |

**判定：FAIL**（W1 未完成，符合预期——本批只验证扫描面安全性，不验证投递）。
**collisions=8 宣布安全**：扫描通过率 31/31，耗时无实质增长，无 panic。

## 说明

1. 本批是单变量对照（相对 -08 仅改 `collisions`），故“无新 panic”可直接归因于该变量安全。
2. 参考的另一半喷洒面（150 fork `spray_children` 持 `/proc/pid/mem`）尚未移植——那是独立的大机制，需单独设计与门禁，不在本批。
3. OQ4（BTF 实测）：`eventpoll` 0xd0，`gen@0xa8`/`refs@0xb0`(8B, hlist_head)/`depth@0xb8`/`refcount@0xbc` 无重叠（§2.6.3 的冲突担忧解除）；`pipe_buffer` 0x28，`flags@0x18`；`+0x166` = ring 第 8 槽内 `+0x26`（`private` 域内）——检查项只能由喷洒数据构造满足（已在 D1 落地：bit 位随喷洒走），内核侧命中仍待真实回收。
4. 单次无 panic 不构成因果结论（`KERNEL-PANIC-01`）。

## 下一步

喷洒面只补了一半（collisions）；`spray_children` fork 群等价物是下一次 L 级设计的主题。在此之前不得标 supported。
