# `fd_graph` 写入原语实施计划（批次 8，L 级，待评审）

**状态：待用户评审。评审通过前不得改动攻击关键路径代码。**

依据：`docs/analysis/fd-graph-primitive-scoping.md`（含指令级证据分级）
门禁证据：`docs/analysis/device-gates/PROFILE-61258-01-20261003-fdgraph-fail.md`

## 1. 动机

6.12.58 profile 侧已确认无缺陷（物理地址对与 12 个几何常量均在真机验证命中），
阻塞点全部集中在 `src/core/route/fd_graph_route.cpp` 的写入原语。首次真机门禁
`chain_hits=0` 并引发 kernel_panic，因此 6.12.58 目前不可用。

目标：把 stub 换成 `preload.so` 证实的 **pipe_buffer 槽位回收 + 受控页写入**机制，
使 W1 能完成，并让成功判定不再依赖自读回。

### 1.1 为什么必须是 fd_graph（三条 route 的现状）

复核结论（2026-10-03）：6.12.58 上**其余三条 route 均已排除**，
fd_graph 不是偏好选择而是唯一候选，因此本 port 无法绕开。

| route | 状态 | 依据 |
|---|---|---|
| `select_stack` | **已证不可行** | 见下 |
| `tcp_zerocopy` | **机制未确认，阻塞** | 见下 |
| `multicast_waiter` | 不支持 | 仅 5.x |

**`select_stack` 不可行**（`tcp-zerocopy-6x-plan.md:19-59`，基于本机 `boot.img`
逐字节反汇编，非推测）：
- 实测 `waiter_shift = 14`（pselect 链 592B − futex 链 576B → Δ112B → 14 qword）；
- 路由可寻址窗口 `global_word ∈ [0,14]`（`PSELECT_ROUTE_NFDS=320` ⇒
  `words_per_set=5`）；
- waiter 需要落在 `[14,27]`；
- 窗口无法扩大：`core_sys_select` 仅在 `round_down(FDS_BYTES(nfds),8) < 43`
  时把 `fd_set` 放内核栈，`nfds=321` 即落到堆，永远无法与栈上 waiter 重叠；
- `[14,27] ∩ [0,14]` 为空。
- 且该结论有**真机代价**：文档记载此前 select_stack 在本内核已导致 **3 次 kernel panic**。
  该结论另有公开 PoC 独立佐证（`tcp-zerocopy-6x-plan.md:379-385`）。

**`tcp_zerocopy` 阻塞**（同文档 §批次 3' 决策门）：
- 批次 1 只证明原语存在、偏移可真实植入用户缓冲区，**未证明**写落点正确；
- 路由把 `waiter_task`/`fake_lock` 写到 `zc[0x28]`/`zc[0x30]`，那是 **6.1 compact 家族**
  布局；本内核 waiter 为 non-compact（`task@0x50`/`lock@0x58`），对不上；
- 硬阻塞：伪造 waiter 由 `prepare_skb_payload` 写入 `heap.current.base`，
  而 zc 的写入目标是 `mapping + page_size`，**不是同一块内存**；
  「谁把哪块内存变成 PI walk 实际走到的 waiter」在本仓库与 git 历史中**均无记载**。
- 用户已明确要求「路线跑通前不碰真机」，故不得试验性真机验证。

**关键结论：tcp_zerocopy 的阻塞点与 fd_graph 的缺口是同一个问题** ——
「写入如何落到内核真正遍历的那个对象上」。`preload.so` 正是这一问题的**已验证答案**
（同机同 kernel `RESULT PASS`），因此 fd_graph 的 port 必须把机制补全，
而不是绕道另选 route。

> 文档漂移（待修）：`tcp-zerocopy-6x-plan.md:195-196` 写「故 profile 保持
> `select_stack`（`waiter_shift = 0`）」，但该 profile 已在 `aed09ad` 改为 `fd_graph`，
> 现无 `select_stack` 块也无 `compact_waiter`。结论本身仍有效（select_stack 不可行），
> 只是「保持 select_stack」的表述已过时。

### 1.2 已解决的部分与真正的缺口

把「写什么」与「怎么送到」分开看，batch D 的范围会小得多：

**已解决且已验证 —— 写什么。** non-compact waiter 几何已在代码库内且双源核对
（`src/core/kernel/target.h:77-85`，并由 `ghostlock-extract boot.img --analysis`
对本镜像独立输出同一组值）：

```
FAKE_WAITER_TREE_PRIO_OFF   = 0x18      FAKE_WAITER_PI_TREE_PRIO_OFF     = 0x40
FAKE_WAITER_TREE_DEADLINE_OFF = 0x20    FAKE_WAITER_PI_TREE_DEADLINE_OFF = 0x48
FAKE_WAITER_PI_TREE_ENTRY_OFF = 0x28    FAKE_WAITER_TASK_OFF             = 0x50
FAKE_WAITER_LOCK_OFF        = 0x58      FAKE_WAITER_WAKE_STATE_OFF       = 0x60
                                           FAKE_WAITER_WW_CTX_OFF         = 0x68
```

且崩溃证据指向的正是这个结构：首次门禁的 pstore 调用栈为
`futex_lock_pi → remove_waiter → rt_mutex_cleanup_proxy_lock → rt_mutex_adjust_prio_chain`，
即内核正在遍历 **rt_mutex PI waiter** 链时被破坏。
换言之，**要写的目标结构是已知的、已验证的，且崩溃本身印证了它。**

**真正的缺口 —— 怎么送到。** 唯一未解决的是「如何把写落到 PI walk 实际遍历到的
那个 waiter 上」：
- `select_stack` 送不到（窗口 `[0,14]` 与所需 `[14,27]` 不交）；
- `tcp_zerocopy` 送不到（写 `heap.current.base`，而 zc 目标是 `mapping + page_size`）；
- `fd_graph` 送不到（stub 把内核地址当 fd，恒 `EBADF`）；
- `preload.so` **送得到**（同机同 kernel PASS）。

因此 batch D 的本质不是「发明一种新原语」，而是**把 preload.so 已验证的投递路径
（epoll fd 图 + `pipe_buffer` `CAN_MERGE` + 命令字驱动的 `write`）移植过来**，
落点沿用上面已验证的 waiter 常量。这与 §1.1 的结论一致：
三条旧 route 与 fd_graph 卡在同一个问题上，而答案就在 preload.so 里。

## 2. 影响文件

| 文件 | 改动性质 |
|---|---|
| `src/core/route/fd_graph_route.cpp` | 重写 `execute()`；新增 `pipe_worker` 线程、**24,576 个嵌套 epoll fd（width 96 × fanout 256）**、240 根管道、fd 表（drain + reclaim 各 `0x780`）、64 KiB 暂存区 |
| `src/core/route/fd_graph_route.h` | 新增成员（worker 句柄、fd 表、暂存区、哨兵、统计） |
| `src/core/profile/model.h` | `FdGraphLayout` 增 4 个 `optional<uint32_t>` |
| `src/core/profile/binary.cpp` | 字段表增 4 项（**顺序须与 Kotlin 一致**） |
| `app/.../data/route/FdGraphConfig.kt` | `entries()`/`apply()`/`from()` 同步 4 键 |
| `app/src/main/assets/kernel_profiles/6.12.58-*.conf` | 填 4 个新字段值 |
| `app/src/test/resources/native-doc-golden.sha256` | 导出字节变化后同步 |
| `docs/kernel_profiles/PROFILE_SCHEMA.md` | 记录新字段语义 |
| 新增 native host 测试 | 几何往返 + 计数器语义 + 生命周期 |

## 3. 分批实施（每批独立过门槛，前一批不过不进下一批）

### 批次 A：移除无效与错误代码（**低风险，建议先做**）

1. 删掉 `fd_graph_route.cpp:264` 的 `splice(..., static_cast<int>(target), ...)`
   —— 内核地址截断成 `0x27c6960` 恒 `EBADF`，是死代码。
2. 修 `collision_page`（`:208`）：`ks->collisions` 是 `size_t` **计数**
   （`kernelsnitch.h:84`），不可当地址。改为真实碰撞页来源，或删除该日志。
3. 修 `reclaim_hits++`（`:277`）语义：现统计「vmsplice 返回 8」，与
   `preload.so` 的 `RECLAIM_HIT` 不同名，避免日志误导。
4. `RACE_SUMMARY` 补 `delay_us` 字段，否则无法定位命中档位。

**理由**：这批不改机制，但去掉了一个恒失败的调用与一处类型误用。
由于 panic 发生在 route 扰动共享对象之后，**移除无效写入有可能直接降低崩溃面**，
且能在下一次门禁中验证「不写是否就不崩」这一关键对照。

### 批次 B：profile 几何扩展（L 级 wire 变更，双侧同步）

新增 `gen`(0xa8) / `refs`(0xb0) / `depth`(0xb8) / `refcount`(0xbc)，
供独立验证用。必须同步 native `binary.cpp` 与 Kotlin `FdGraphConfig`（键名逐字一致、
顺序一致），并更新 golden 哈希。

**前置（已解除）**：这 4 个偏移已由 **6.12.58 自身的 BTF** 确认 ——
`capture/btf.vmlinux`（6,912,706 B，`magic=0xeb9f v1`，`type_len=4,189,380`，
`str_len=2,723,302`）。来源可信：`work/target_offsets_disasm.conf` 头部声明
`release = "6.12.58-android16-6-gff10eaa8f8a4-ab15575650-4k"`，且其 `task_struct`
取值与仓库 profile **逐项一致**。

```
struct eventpoll  size = 0xd0 (208)
  gen             @ 0xa8 (168)
  refs            @ 0xb0 (176)   8 字节 -> 不是 hlist_head(16B)，故与下一项不重叠
  loop_check_depth@ 0xb8 (184)   4 字节
  refcount        @ 0xbc (188)   4 字节
```

同一份 BTF **反向印证**了 profile 中已有的 5 个结构派生常量：
`eventpoll_size=208`、`epitem_ep=0x48`、`epitem_fllink=0x50`、
`pipe_buffer=0x28`、`pipe_flags=0x18`。

⇒ **本批已撤销「preload.so 那 4 个值是通用值、未经验证」的判断** ——
它们对本内核是正确的。

**状态：已完成**（`f71f37b`）。双侧顺序经机械比对一致（`binary.cpp` /
`FdGraphConfig.entries()` / `RouteFdGraphFields` / profile 四表全等）。

### 批次 C：补齐机制证据（只读分析，零代码风险）

反汇编 `preload.so` 的编排函数，把 scoping §2.3 的推断升级为指令级事实。

**已确认**（scoping §2.4）：全部五个阶段格式串落在**单个** 8356 字节函数
`0x2205a8`；其 syscall 清单为 `epoll_ctl`×7、`read`×2、`write`×1，
**`splice`/`vmsplice`/`tee` 各 0 次**。故：原语是 **epoll fd 图**
（7 次 `epoll_ctl` 操纵 `epitem.fllink`），payload 经**单次 `write`** 投递。

**待确认**：

1. ~~7 次 `epoll_ctl` 的参数序列~~ → **已确认**（scoping §2.5.1）：6×`EPOLL_CTL_ADD`
   把同一目标 fd 注册进多个 epoll 实例以拉出 `epitem.fllink` 宽图，
   1×`EPOLL_CTL_DEL(event=NULL)` 摘链（即 `decoy_unlink`）。
2. ~~单次 `write` 的目标 fd~~ → **已确认**（§2.5.2）：`write(fd_table[4], buf, count)`，
   是**普通 fd**；且由命令字驱动（`read(fd,&c,1)`，`c=='W'` 才写）。
3. **部分确认**（§2.5.4）：编排函数含 `getrlimit`×6 / `setrlimit`×4
   → 抬 `RLIMIT_NOFILE` 取得 fd 额度；配合日志里的 `fds=1964` / `fds=1005`，
   说明「fd graph」是**批量开 fd（千级）+ 注册进 epoll** 形成的宽图，
   7 次 `epoll_ctl` 只是收尾结构操作。
   **回收手段已确认**（scoping §2.7）：`fcntl(fd, F_SETPIPE_SZ, bytes)` 缩放管环
   后 `F_GETPIPE_SZ` **回读校验**（`cmp w0, w22` 不符即失败退出）——
   即日志里的 `resize_sample`。缩容走 `pipe_resize_ring()` 释放旧
   `pipe->bufs`，产生 `pipe_buffer` 槽位 UAF 窗口；回读是必要条件而非可选确认。
   **仍未确认**：`fake_count` 的落点、`EPOLL_CTL_DEL` 在其中的确切角色、
   `fake_fllink` 偏移量 `+8` 的选取依据（**毒值形式已确认**，见 scoping §2.8：
   `fake_fllink = base | 0x108 = LIST_POISON1 + 8`）。
4. **仍未确认**：`gen`/`refs`/`depth`/`refcount` 四个偏移在 6.12.58 上的真值。
   `preload.so` 串里的 `0xa8/0xb0/0xb8/0xbc` 是通用值；main 分支源码
   推算与该串**不自洽**（`refs` 若在 `0xb0` 占 16B 至 `0xc0`，与
   `depth=0xb8` 冲突），故不可替代。需 6.12.58 的 BTF 或真机读回（批次 B 前置）。
5. **含义已确认；写入点改为实现期实测**：bit4 = `PIPE_BUF_FLAG_CAN_MERGE`
   （scoping §2.6.1，置位后 `pipe_buf_merge()` 可不拷贝直接串接页，
   是把受控页挂进管环的前提）。
   在 `pipe_buffer.flags`(0x18) 上的**具体写入指令静态追查已放弃** ——
   两个候选均被证伪（scoping §2.5.5 第 3 条），该 stripped 二进制上的
   偏移字面量搜索不可靠。**改为批次 D 实现期间用实测/打点确认。**

**批次 D 的设计约束已明确**：写入目标是普通 fd + 命令字驱动，
不涉及把内核地址当 fd；建图需先扩 `RLIMIT_NOFILE` 并批量开 fd。

### 批次 D：实现回收 + 受控写入

> **⚠ 2026-10-03 大幅修正**：原计划把批次 D 理解为「240 根管道」。
> 取证（scoping §2.14/§2.16/§2.18）证明 **240 只是 `pipe_buffer` 回收表槽数**，
> 与「24,576 个嵌套 epoll 构成的宽 `epitem.fllink` 链」是**两个独立机制**。
> 按原计划实现，图会窄约两个数量级。以下为修正后的顺序。

批次 C 已把投递链各环的**取值**确认完毕，因此本批不再需要取证，
按 scoping §2.7–§2.18 照做即可。依赖顺序与已确认取值：

1. **抬 `RLIMIT_NOFILE`**（scoping §2.14）：`getrlimit` 后要求
   `cur >= 当前占用 + 0x60a0 (24736)`，不足则 **`exit(-1)`** 致命退出。
   **此步在前**，否则后续 `epoll_create1` 会在中途 `EMFILE`。
2. **构建嵌套 epoll 图**（scoping §2.16，**原计划遗漏**）：
   外层 `width = 96 (0x60)`、内层 `fanout = 256 (0x100)`，每轮
   `epoll_create1(EPOLL_CLOEXEC)` 新建实例，再用
   `epoll_ctl(new, EPOLL_CTL_ADD, prev_epoll_fd, &event)` 把**上一个 epoll 的 fd**
   注册进去；`epoll_ctl` 返回非 0 即致命退出。
   合计 `96 * 256 = 0x6000 = 24576` 个 epoll。
   `epoll_event.data` 由 `{uVar33, prev_fd}` 组成。
   日志：`GRAPH_READY width=96 fanout=256 edges=24576`。

   > **⚠️ fd 预算硬约束（本计划新增，务必遵守）**
   >
   > 依 `preload.so` 实测日志：`current=952`、`limit_cur=32768`。
   > ```
   > 图本身  24576 fd  =  进程 fd 表的 75%
   > + 管道   240 fd
   > 峰值     25768 fd  =  78.6%，仅余 ~7000 余量
   > ```
   > 由此产生三条**实现约束**：
   > 1. **建图窗口内不得有任何其他 fd 分配** —— 日志、握手、fork、
   >    payload 构建都不得在此窗口打开 fd，否则中途 `EMFILE` 且**致命**
   >    （图是不完整的，无法回退）。
   > 2. **`pipe_worker` 线程与 240 根管道必须在建图之后创建**，
   >    不得与建图并发持有 fd。
   > 3. **`limit_cur` 不是「越大越好」**：上限就是进程 fd 表，
   >    盲目调高会挤掉进程自身（session、日志、后续 W2/W3 步骤）的余量。
   >    参考实现只要求 `≥ current + 0x60a0`，**照此即可，不要上调**。
   >
   > 这也是 `tools/gate_preflight.py` 的 `nofile` 检查存在的理由：
   > 它把「建图中途 `EMFILE`」从一次设备崩溃前移为一次前置 FAIL。
3. **fd 表**（§2.10）：`malloc(0x780)`（或等效 `mmap`），`memset 0xff`；
   240 槽 × 8 字节步长。**空槽初值必须是 `-1`，不得用 `0`**
   —— stub 现写 `0`，等于把 fd 0（stdin）当有效管道。
4. **每槽建管道**（§2.10）：240 根，fd 写回对应槽位。
5. **两级缩放**（§2.7）：`fcntl(fd, F_SETPIPE_SZ, n<<12)`，
   `reclaim_small` 用 `n=2`（8 KiB）、`reclaim_expand` 用 `n=0x20`（128 KiB）；
   每次都必须 `fcntl(fd, F_GETPIPE_SZ)` 回读并要求 `observed == requested`。
   **失败是致命的**（原实现记 `resize_fail` 后 `exit(-1)`），
   故必须在投递前处理失败，不可失败后重入。
6. **`late_refs`**：诱饵 unlink + fd preflight。
7. **槽位选取与 `RECLAIM_HIT`** 两模式（scoping §2.18.2，判据已精确）：
   - `pipe_flags_candidate`（`param_1 & 1 == 0`）：需 `chain_hit == 1`
     **且** `bit4 == 1`，日志 `FLAGS_CANDIDATE` → `RESULT PASS`；
   - `zero_byte_redirect`（`param_1 & 1 == 1`）：需 `chain_hit == 1`，日志 `CHAIN_HIT`。
   `fake_count = 0x10`（16 项重定向表）。
8. **`fake_fllink`**（§2.8）：`base | 0x108`（`LIST_POISON1 + 8`）。
9. **`CAN_MERGE`：本批不再需要定位写点**（scoping §2.18.2，**原第 7 项作废**）。
   参考实现是在喷入后**读回** `*(u8 *)(pipe_slot + 0x166)` 并测 bit 4，
   即只需保证**偏移 `0x166` 的 bit 4 落在我们喷入的数据里**。
   喷入数据的构造因此必须把该偏移的 bit 4 置位 —— 这是**数据构造要求**，
   不是**指令写入点定位要求**。原先三个被证伪的静态候选无需再追。
10. **喷入标记 `GENMARK0`**（scoping §2.19.1，**已由 `preload.so` 成功日志确认**）：
    向 `epitem.generation`（偏移 `0xa8`）写入 ASCII 标记
    `0x304b52414d4e4547`（小端 = `"GENMARK0"`），约 **68 份**
    （参考日志首轮 `depth=68`，即 `outer_depth`）。
    `marker_changed` 判据即「`epitem.generation` 是否已不再读回 `GENMARK0`」：
    读到标记 = 未被回收；读到别的 = 回收成功。
    **此步是回收检测的唯一依据，缺失则整批无法判定成败。**
11. **payload 投递**（§2.9）：命令字 `'W'` 门控；
    240 路 `write(fd_table[i], payload, len)`，**每次必须返回完整长度**，
    否则整轮放弃。
12. **回读**（§2.9）：`pread64` 按**槽位偏移**校验（日志 `PIPE_OBSERVED`），
    而非顺序 `read`。
13. **有界重试循环**（scoping §2.19.2，**新增要求**）：
    - `delay_us` 阶梯**自 0 递增**（参考日志 0, 1, 2, …）；
    - **成功判据是 `chain_hit == 1` 且 `bit4 == 1`**，
      单纯 `chain_hit == 1` **不算成功**（参考日志 round=1 即 `chain=1 bit4=0`）；
    - **成功可能发生在第 0 轮**（参考日志另一次运行 round=0 即 `chain=1 bit4=1`）
      ⇒ 不得把首轮未命中当作机制无效的证据，必须重试到上限再判失败。
14. **`pipe_worker` 线程模型**：持槽 + 与主线程握手（§2.5.3 的自旋点）。
15. **顺序不变量 `close_after_trigger=1`**（scoping §2.18.1，**硬约束**）：
    epoll fd 必须在**触发之后**才 `close`。先 close 再触发会让被摘除的 epitem
    提前离开链，内核不再遍历到投毒项 —— 必失败。
16. **`redirect` 的 fork 模型**（scoping §2.17）：投递由**子进程**执行，
    父进程带 `timeout_s = 0xf0 (240s)` 等待并回收 `rc`。
17. 撤销 stub 把内核地址当 fd 的 `splice()`（恒 `EBADF`）—— **批次 A 已完成**。

> 与批次 A 的关系：批次 A 已单独完成并提交（`7e84335`），第 15 项由其覆盖。
> 批次 A **仍应先单独跑一次门禁** —— 它是「不写是否就不崩」的唯一干净对照，
> 这个因果结论无法在机制实现后再获得。

### 批次 E：独立验证

**判据已由 scoping §2.17.1 改定**：参考实现读 **`/sys/fs/selinux/enforce`**，
首字节 `!= '1'` 即视为写入生效；失败重试一次，仍失败则 `return -1`。

```c
if (redirect(attempt=1) && read("/sys/fs/selinux/enforce") == '1') {
    if (redirect(attempt=2) && read("/sys/fs/selinux/enforce") == '1') return -1;
}
```

**这必须替换 stub 的 `*verify == value` 自读回**（`fd_graph_route.cpp:267`）——
自读回经由同一次写读回目标，**无法区分「写到目标」与「写到邻居」**，
它不是较弱形式的验证，而是**不构成验证**。

批次 B 的 `generation`/`refs`/`depth`/`refcount` 哨兵**保留用于诊断**
（参考实现的 `RACE` 行确实打印 `generation` 与 `depth`），
但**不再是验收判据**，且批次 E **无需新增 profile 字段**。

**依赖**：① 批次 D 已实现；② `/sys/fs/selinux/enforce` 可读。
② 不再依赖批次 B 的哨兵挂载位置，故依赖关系较原计划更松。

**在批次 E 落地前**，批次 D 先用 `preload.so` 同款口径记录诊断量：
每次 `write` 返回全长 + `pread64` 按槽位偏移读回（`PIPE_OBSERVED`），
记为 `chain_hits`；**不以** `*verify == value` 为准（stub 现状即此法，无区分力，
见 scoping §2.5.2 与门禁记录中 `chain_hits=0` 的教训）。
这些仅为**诊断**，不是验收判据 —— 验收判据见上（`/sys/fs/selinux/enforce`）。

### 批次 F：真机门禁

**必须冷启动**；固定 CPU 对；单 route；KernelSU 未加载。

## 4. 所有权与生命周期审查（AGENTS.md 强制，批次 D 适用）

| 对象 | 起点 | 所有者 | 访问者 | 终结点 | 释放者 |
|---|---|---|---|---|---|
| `epoll_fd` / `pipe_read` / `pipe_write` | `prepare()` | `FdGraphRoute`（`UniqueFd`） | consumer 线程 | `destroy()` | `reset()`；stuck 时 `retain_for_process_lifetime()` |
| `consumer_thread` | `prepare()` | `PthreadOwner` | `disarm()` | join 后 | `release()` |
| **`pipe_worker`（新增）** | 批次 D | `PthreadOwner` | 主线程等待其 payload 写 | **必须先于 pipe fd 关闭** | `request_stop()`+`join()` |
| **24,576 个嵌套 epoll fd（新增，批次 D 第 2 步）** | 批次 D，`epoll_create1(EPOLL_CLOEXEC)` | `FdGraphRoute`（批量 fd 数组） | **仅** `epoll_ctl` 建链期间访问 | `disarm()`/`destroy()`，**且必须晚于 `pipe_worker` join** | 逐个 `close()`；数量大，需分批释放并检查 `EBADF` 不影响其余 |
| **240 根管道（新增）** | 批次 D，`pipe2()` | `FdGraphRoute` | worker 经 `table[i]` 取 fd | `disarm()`/`destroy()` | 逐个 `close()`；stuck 时并入兜底 |
| **fd 表（新增，两张）** | 批次 D，`malloc(0x780)` | `FdGraphRoute` | worker **仅在投递窗口内** | `destroy()` | `free()` |
| **用户态暂存区（新增）** | 批次 D，`malloc(0x10000)` + `memset 0x42` | `FdGraphRoute` | 建表 → 喷入内核 | **必须晚于喷洒完成** | `free()` |
| **槽位引用（新增）** | 批次 D | worker 线程 | 主线程**不得**在 free 后访问 | worker 停止访问后 | 内核侧（受控对象） |

#### 4.1 新增对象带来的三条生命周期约束

批次 C 确认了投递链的形状（scoping §2.9–§2.12），由此产生三条
**既有代码里不存在、必须新增**的约束：

1. **暂存区必须活过喷洒。** 受控表在 64 KiB 用户态缓冲里构造
   （§2.12），再被复制进刚释放的管环。因此 `free()` 暂存区必须发生在
   「喷入内核」完成**之后** —— 这是最容易被写错成「进 `execute()` 就 RAII 收掉」
   的地方，且写错不会立刻崩，只会让下一次喷洒拿到已释放内存。
2. **fd 表的空槽语义是 `-1`。** 原实现用 `0xff…ff` 作「未填充」标记（§2.10）；
   stub 用的 `0` 是 **fd 0（stdin）**。批次 D 必须沿用 `-1`，否则会把 stdin
   当成有效管道写入 —— 这是一个**语义反转**，不是笔误。
3. **240 根管道的 fd 与槽位必须成对回收。** 表项是 8 字节槽里的 fd，
   关闭时须按同一索引走，不得依赖 fd 连续性。

必须遵守的既有顺序（重构不得改变）：

1. 所有参与者**停止访问** → join worker → 再 unlink/释放管道槽。
2. `disarm()` 必须在 `destroy()` 之前（`do_fd_graph_fake_lock_route` 已如此）。
3. `consumer_stuck` 的既有兜底路径（`retain_for_process_lifetime()` +
   `ROUTE_DIRTY_FAILURE`）**保持不变**，新增 worker 与 240 根管道也要纳入该判定。

**UAF 边界**：被回收的 `pipe_buffer` 槽位是漏洞原语（**唯一**允许的
use-after-free）；辅助对象、race 状态、**fd 表**、**暂存区**、同步资源
**一律不得**跨回收点访问。

## 5. 验证计划（每批门槛）

批次 A/B/E（普通改动）：

```sh
make -C src native-host-tests
make -C src ghostlock          # NDK 构建零警告
make -C src lint-tidy          # 0 findings
./gradlew :app:testDebugUnitTest
./gradlew exportKernelProfiles
```

批次 D/F（攻击关键路径）—— 门槛全量：

1. `python3 tools/cmp_disasm.py <baseline> build/native/ghostlock`
   对 8 个攻击函数做逐函数核对；字节差异无法证明不影响
   「攻击代码 ↔ 资源准备/回收」顺序时，**停止该批次并调查**。
2. 真机门禁：**冷启动**、固定 CPU 对、单 route、KernelSU 未加载。
3. 日志归档至 `Download/ghostlock-debug-log/<时间>/`，按
   `docs/analysis/device-gates/` 格式记录（失败与成功同等归档）。
4. 核心攻击函数的资源准备/存活期/回收代码须反汇编核对相对顺序不变。

## 6. 风险与停止条件

- **已知**：历史上有「重构漏回收 PI 内存导致 panic」的先例；本计划触及
  同类资源（管道槽），批次 D 必须逐条过 §4 的审查表。
- **归因限制**：`KERNEL-PANIC-01` 允许同构建 PASS/panic/PASS；
  判定因果要求同构建复现 + 冷启动复跑，不得凭单次结果。
- **批次 C 已完成**（scoping §2.4–§2.12）：投递链各环取值均已确认，
  **不再是批次 D 的前置**。批次 D 可以直接进入实现。
- **停止条件**：
  - 批次 A 后真机仍 panic 且 `chain_hits` 仍为 0 → 说明破坏源不在无效写入，
    需回到批次 C 重新定位，不得继续叠加机制。
  - `cmp_disasm` 出现无法解释的攻击函数差异 → 停止并调查。
  - **批次 B 在拿到 6.12.58 BTF 前不得填值。** 已确认无路可走：
    设备为 production build（`adb root` 拒绝、`/sys/kernel/btf/vmlinux` 拒绝读取）；
    工作区 `work/target_Image.bin` 是 `ANDR` boot 镜像容器而非裸 kernel Image，
    6 处 BTF magic 候选**全部通不过 header 校验**；
    main 分支源码推算与 `preload.so` 串**不自洽**（scoping §2.6.3），
    故不可替代。**批次 B 与批次 E 均因此阻塞，不阻塞 A 与 D。**
  - 批次 D 中 `CAN_MERGE` 写入点若实测无法定位 → 停止该步并重新取证，
    **不得**以猜测的偏移硬编码。
- 批次 A/B 之间若真机不再 panic，仍**不得**标记 6.12.58 为 supported：
  `chain_hits` 未成功即 W1 未完成。

## 7. 评审要点

批次 C（只读分析）**已完成**，结论见 scoping §2.4–§2.12。
当前可执行的是 **D**（A 亦可，但见 §7 的次序建议）；**B 已完成，E 已解锁**。

请确认：

1. **批次顺序**：是否认可 **先 A 再 D**？
   - A 低风险，且是「不写是否就不崩」的唯一干净对照（批次 D 一旦实现，
     该因果结论就再也拿不到了）。
   - D 已具备全部取值（§3 批次 D 的 11 步），不再有取证前置。
   - B 已完成，E 已解锁，不再有外部依赖。
2. **批次 D 的实现范围**：本批只做「投递机制」（fd 表 + 240 根管道 + 两级缩放 +
   240 路 `write` + `fake_fllink` + `pread64` 回读），
   **不含** `CAN_MERGE` 写入点（静态追查已封顶，须实现期实测）。
   是否接受这一拆分？
3. **§4.1 的三条生命周期约束**是否已足够：其中「暂存区必须活过喷洒」
   与「空槽语义 `-1` 而非 `0`」是批次 D 最易写错的两点，
   写错都不会立刻崩（后者是把 stdin 当管道，前者让下次喷洒读到已释放内存）。
4. **验收判据**：批次 D 的成功判据建议沿用 `preload.so` 的形态 ——
   每次 `write` 返回全长 + `pread64` 按槽位偏移读回（`PIPE_OBSERVED`），
   **不以** `*verify == value` 自读回为准（stub 现状即此法，无区分力）。
   是否认可改用 `chain_hits`/`bit4_hits` 口径？