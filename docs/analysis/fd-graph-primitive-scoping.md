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

### 2.3 推断（尚需反汇编确认）

回收 `pipe_buffer` 槽位 → 使其指向**受控页**（`preset_direct_map`）→
`pipe_worker` 线程向该槽写入（`payload_writes`）→ 写入落到 `controlled_page`。

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

> 尚未确认（需批次 C 续做）：7 次 `epoll_ctl` 的具体参数序列，
> 以及 `write` 的目标 fd 如何指向被回收的 `pipe_buffer` 槽位。
> 这两点决定批次 D 的实现细节。

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
| `fllink` | 无 | `KNOWN_PAGE fake_fllink` |
| `pipe_flags` | 无（只打印偏移 0x18） | `pipe_flags_redirect` 改写 bit4 |
| 写入 | `splice(..., static_cast<int>(target), ...)` ← 内核地址当 fd，必然 `EBADF` | `pipe_worker` 写受控槽位（**不用 splice**） |
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

1. `late_refs`：诱饵 unlink + fd preflight。
2. 活跃槽位选取与 `RECLAIM_HIT` 两模式判定。
3. `fake_fllink` 构造 + `pipe_flags`(0x18) bit4 改写。
4. `pipe_worker` 线程模型：持槽 + `payload_writes` + `resize_sample`。
5. 每档 delay 的**多次重试与统计**（stub 每档只试 1 次，且 `RACE_SUMMARY` 未记录 `delay_us`，
   无法定位命中档位）。
6. 独立验证（哨兵 + carrier readback），替换自读回。
7. 撤销 stub 中把内核地址当 fd 的 `splice()` 调用（该调用恒 `EBADF`）。

## 7. 下一步

L 级改动（攻击关键路径），按 `AGENTS.md` 需先出计划文档并获认可再动代码。

1. 反汇编 `0x2205a8..0x22264c`（含 `RACE_SUMMARY` / `RECLAIM_HIT` 格式串的函数）
   与 `pipe_worker` / `redirect` 处理函数，把 §2.3 的推断升级为指令级事实。
2. 据此产出实施计划，含所有权/生命周期审查（需在管道槽与 slab 对象间建立新持有关系）。
3. 实现后重跑门禁；**必须冷启动**，且按 `AGENTS.md` 需同构建复现来判定因果。

在第 1 步完成前不要改动 `fd_graph_route.cpp`：现有 `prepare/execute/disarm/destroy`
形状与 12 个常量是重写时的对照基准。