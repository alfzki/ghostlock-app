# PROFILE-61258-01 真机门禁：6.12.58 fd_graph（direct）— FAIL

对应提交 `b2d0e6c`（`fix(profile): correct the 6.12.58 physical address pair and ungate it`）
与 `2a245aa`（`fix(profile): write fd_graph geometry into the native document`）。
候选二进制 `build/native/ghostlock` SHA-256
`2800342d3c5a133e37bba0e193265d43db21572657e9e5f4604dcdbc9d9c0cd0`（md5
`659e9e50eb7a819618414a74d96f17df`）。设备端 profile sha256
`8cf90e311a7747106bb97f9d196942d698778dbf530abbac9028e3c90c184fe8`（md5
`e2f3f2ddc0e67b39ce6b523e13a8bbbf`），与 `native-doc-golden.sha256` 中 `6.12.58` 一行相同，
即设备使用的正是批次 1b/2c 修正后的导出文档。App 构建 `GhostLock 1.2+563 build
2026-10-03 15:44:16`。

## 设备与入口

- 型号 V2514（vivo X300 Pro，MT6993，16GB）；`uname -r` =
  `6.12.58-android16-6-gff10eaa8f8a4-ab15575650-4k`。
- 入口：App 内 Run（`lib/arm64/libghostlock.so` 以 App 身份拉起，非 CLI、非 Shizuku）。
- 单 route（`fd_graph`）、CPU 对 0/1（来自 profile）；`uid=10528 euid=10528`
  `attr=u:r:untrusted_app:s0:c16,c258,c512,c768`，`Seccomp=2 Seccomp_filters=1`
  （App 路径有 seccomp 过滤，W3 需要真实通过）。
- **门禁条件未满足**：本次为**非冷启动**，`boot_ms=42853`（≈43s）。KernelSU 加载状态未记录。

## 结果

**FAIL — 强制重启，`ro.boot.bootreason = kernel_panic`。**

进程在 fd_graph route 内未能完成写入，随后约 17 秒内核 panic。关键日志
（`PROFILE-61258-01-20261003-fdgraph-fail.native.log`）：

```
[*] soc: mtk; kernel_phys_load=0x80000000
[*] p0 profile ... phys_offset=0000000080000000 kernel_phys_load=0000000080000000 delta=0000000000000000
[*] W1: SELinux attempt 1/15
[*] === W1: SELinux === target=0xffffff80027c6960 mode=1 leaf=0
[*] [route] CMP_REQUEUE_PI ret=-1 errno=35; waiting route_done
[*] fd_graph route geometry: eventpoll_size=208 epitem_ep=72 epitem_fllink=80 pipe_buffer=40
    pipe_flags=24 pipe_slots=32 pipe_ring=1280 pipe_object=2048 graph_width=96
    graph_fanout=256 graph_edges=24576 objects_per_order3=16
[*] fd_graph: collision page found at 0000000000000002
[*] fd_graph: RACE_SUMMARY tries=10 reclaim_hits=10 chain_hits=0 bit4_hits=0
```

- `chain_hits=0 bit4_hits=0`：10 次尝试**没有一次**写入被验证成功（`fd_graph_route.cpp:268`
  的 `*verify == value` 从未成立），W1 未完成。
- `collision page found at 0000000000000002`：`fd_graph_route.cpp:208` 把
  `ks_owner.get()->collisions`（`kernelsnitch.h:84` 中是 `size_t collisions`，**计数**）
  当作页地址打印。该值仅用于日志，未参与写入。

### 本次门禁确认成立的项

1. **物理地址对已修正并生效。** `target=0xffffff80027c6960` 与 `preload.so` 在同机同
   kernel 的成功记录（`direct_map_alias=0xffffff80027c6960`、
   `STAGE selinux_zero target=0xffffff80027c6960`）**逐位相同**，`delta=0` 表明两字段在
   换算中抵消。批次 2b 之前该 profile 会算出 `0xffffff81027b6960`（偏 `0xffff0000`）。
2. **fd_graph 几何已到达 native。** 日志打印出全部 12 个常量，确认批次 2c 的
   `FdGraphConfig.from()` 前缀缺失问题已修复（此前导出的 GLK1 文档完全不含 `route.fd_graph`）。

### 内核侧证据（`PROFILE-61258-01-20261003-fdgraph-fail.pstore.txt`）

```
[   61.622150][T14586] Unable to handle kernel paging request at virtual address 0000000100000018
[   61.622163][T14586]   ESR = 0x0000000096000005
[   61.622174][T14586]   FSC = 0x05: level 1 translation fault
[   61.622193][T14586] [0000000100000018] pgd=0, p4d=0, pud=0
[   61.639002][T14586] Call trace:
[   61.639084][T14586]  rt_mutex_adjust_prio_chain+0x220/0x7c0
[   61.639087][T14586]  remove_waiter+0x180/0x1ec
[   61.639090][T14586]  rt_mutex_cleanup_proxy_lock+0x50/0x94
[   61.639092][T14586]  futex_lock_pi+0x2b8/0x45c
[   61.639095][T14586]  __arm64_sys_futex+0x238/0x390
```

- 崩溃位于 **CVE-2026-43499 原语本身**（`remove_waiter` → `rt_mutex_cleanup_proxy_lock`
  → `rt_mutex_adjust_prio_chain`），解引用未映射地址 `0x0000000100000018`。
- **panic 任务 `T14586` 不是 GhostLock**：本机 GhostLock 为 `T11660`（`libghostlock.so`，
  与 App 日志 `pid=11660` 一致）。
- 时间差：GhostLock 运行于 ≈42.8–45s，panic 于 61.6s，**相隔约 17 秒**。

## 根因分析（postmortem 口径）

- **影响**：一次强制重启（kernel_panic），手机重启。运行期约 17 秒后由无关进程触发。
- **直接原因**：`fd_graph` route 的写入原语是空实现。
  `fd_graph_route.cpp:264` 将内核地址当作文件描述符传给 `splice()`：
  `splice(pipe_fds[0], nullptr, static_cast<int>(target), nullptr, 8, SPLICE_F_MOVE)`。
  `target=0xffffff80027c6960` 截断为 `0x27c6960`（41,707,872），不是合法 fd，`splice()`
  必然返回 `EBADF`。因此写入从未发生，与 `chain_hits=0` 一致。
- **为什么内存仍被破坏**：route 的 spray/race 机械（mm_struct 泄漏、kernelsnitch 扫描、
  reclaim/drain 缓冲）仍会扰动共享的内核对象，而 route 又没有取得受控写入来收尾。
  17 秒后无关进程遍历被污染的 rt_mutex waiter 链而 fault。
- **归因限度（重要）**：本次**不满足冷启动**，且按 `AGENTS.md`「同构建可 PASS/panic/PASS」，
  **单次 panic 不足以判定因果**。上述「污染外溢」是当前证据下最自洽的解释，但仍是**假设**，
  需同构建复现 + 冷启动复跑来确认。

## 日志

- `PROFILE-61258-01-20261003-fdgraph-fail.native.log` —— App 运行日志
  （设备端 `Download/ghostlock-debug-log/20261003-172124/ghostlock-direct-0.log.txt`）。
- `PROFILE-61258-01-20261003-fdgraph-fail.pstore.txt` —— `/data/debuglogger/console-ramoops-0`
  的 panic 片段（完整 2MB 见仓库外 `pstore-dump-1722.txt`）。

## 变更说明

本次验证针对的行为差异共三项：

1. `6.12.58` 的 `kernel_phys_load` / `kernel_phys_offset` 由被构建机 `/proc/iomem` 污染的
   `0xffff0000` / `0` 改为相等的 `2147483648`（批次 1b）。**结果：W1 目标地址与真机已验证
   地址一致，该项确认修复。**
2. `fd_graph` 12 个几何常量首次真正写入 GLK1 文档（批次 2c）。**结果：native 侧收到全部
   12 个常量，该项确认修复。**
3. 首次真机运行 `fd_graph` route。**结果：写入原语为空实现，route 未能完成 W1，并导致
   kernel_panic。**

因此：**profile 侧已无已知缺陷；阻塞点转移到 `fd_graph` route 的写入原语。**
在 route 实现真正的 UAF 写之前，6.12.58 不具备可用状态，不得标记 supported。