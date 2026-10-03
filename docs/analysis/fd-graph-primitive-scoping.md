# `fd_graph` 写入原语 scoping（2026-10-03）

对比 `preload.so`（本机验证可 root）与 `src/core/route/fd_graph_route.cpp` 的实现，
回答「stub 缺了什么」。配套门禁记录：
`docs/analysis/device-gates/PROFILE-61258-01-20261003-fdgraph-fail.md`。

## 结论

**移植只搬走了「词汇表」和「几何常量」，没有搬「机制」。**
stub 复用了 `preload.so` 的 12 个几何常量与日志字段名，但写入路径是一段空实现，
在真机上 10 次尝试全部失败（`chain_hits=0`），并导致 kernel_panic。

## 证据来源与其局限

- `preload.so`：**完全 stripped**（`nm` 符号数 0），静态链接，NDK r29 (14206865)。
  因此本 scoping 基于**字符串表 + 它自己的运行日志**，**不是反汇编**。
  字符串保留了 `pr_*` 格式串，足以还原参数与流程；函数边界与寄存器级语义需反汇编确认。
- 参考运行日志：`preload-full-log.txt`（`RESULT PASS`，同机同 kernel）。

## `preload.so` 实际做的事

从格式串可还原出与写入直接相关的参数集：

```
count=%zu vmsplice_pages=%d file_slot=%d target_offset=%lld fds=%d
target=%s offset=%lld payload=%zu pipe_slots=%d pipe_buffer=0x%x ring_request=0x%x
    ring_object=0x%x objects_per_order3=%d active_slot=%d drain_count=%zu reclaim_count=%zu
KNOWN_PAGE base=0x%016llx fake_fllink=0x%016llx
phase=collision_shape fds=%d pre=%zu post=%zu
vmsplice index=%zu advance=%zd expected=%zu errno=%d
RACE round=%d ... returned_len=%u returned_sources=%u generation=0x%016llx depth=%u
    marker_changed=%d chain_hit=%d bit4=%d ...
FLAGS_CANDIDATE round=%d chain_hit=1 bit4=1
CHAIN_HIT mode=zero round=%d target=0x%016llx
pipe_flags_redirect
```

由此可归纳出它的写入链（**推断，需反汇编确认**）：

1. **选一个活跃管道槽**：`active_slot`（在 `pipe_slots=32` 个槽里挑一个），
   配合 `drain_count` / `reclaim_count` 做回收与排空计数。
2. **用 `vmsplice` 把「碰撞页」推进管道**：注意是 `vmsplice_pages`（多页），
   且推进量要校验（`advance=%zd expected=%zu`）——不是随便塞 8 字节。
3. **按 `target_offset` 落写**：写目标是 `base + offset`（`target=%s offset=%lld`），
   **不是把内核地址当 fd 传给 `splice()`**。
4. **伪造 `fllink`**：`KNOWN_PAGE base=... fake_fllink=...` —— 构造受控的
   `epitem->fllink`，这是把后续遍历重定向到目标的关键。
5. **`pipe_flags_redirect`**：改写 `pipe_buffer.flags`（偏移 `0x18`）以改变内核
   对该 buffer 的处理路径。
6. **形状校验**：`phase=collision_shape pre=%zu post=%zu` 确认碰撞结构在操作前后
   符合预期形状。
7. **标记验证**：`generation` / `depth` / `marker_changed` / `chain_hit` / `bit4`
   用于判定写入是否真的落到了目标（`CHAIN_HIT mode=zero` 即成功分支）。

`preload.so` 自身也有多条 `RESULT FAIL` 分支（含
`RESULT FAIL epoll_probe reason=carrier_readback_mismatch chain_hit=1`），
说明它并非稳定成功，其成功条件同样需要设备门禁验证。

## stub 实际做的事

`src/core/route/fd_graph_route.cpp`：

| 环节 | stub 实现 | 结论 |
|---|---|---|
| 几何常量 | 仅用于 `pr_info` 打印（150-155 行） | `epitem_fllink` / `pipe_flags` **只打印，未使用** |
| reclaim/drain | `mmap` 匿名缓冲 + `memset 0xff` + 填 0（171-193 行） | 无 fd、无槽位、无计数语义 |
| 碰撞页 | `reinterpret_cast<uint64_t>(ks->collisions)`（208 行） | 把**计数**（`kernelsnitch.h:84` 的 `size_t collisions`）当地址；仅用于日志 |
| 写入 | `vmsplice(pipe_fds[1], iov, 1, 0)`，`iov` 是 8 字节**用户缓冲** | 非 `vmsplice_pages`，无 `advance` 校验 |
| 落写 | `splice(pipe_fds[0], nullptr, static_cast<int>(target), nullptr, 8, SPLICE_F_MOVE)`（264 行） | **把内核地址截断成 `0x27c6960` 当 fd**，必然 `EBADF` |
| `fllink` | 无 | 缺失 |
| `pipe_flags` 改写 | 无 | 缺失 |
| `active_slot` / `target_offset` | 无 | 缺失 |
| 形状/标记验证 | 无 | 缺失 |

日志中 `collision page found at 0000000000000002` 正是「计数 2 被当地址打印」的直接体现。

## 缺失清单（按依赖顺序）

1. **活跃槽位选择**（`active_slot`）与其回收/排空计数——后续一切的前提。
2. **`fake_fllink` 构造**：受控的 `epitem->fllink` 重定向。
3. **`pipe_flags` 改写**（`pipe_flags_redirect`）。
4. **以 `base + target_offset` 为落点**的正确 `vmsplice`/`splice` 序列，
   并校验 `advance` 与 `returned_len`。
5. **形状与标记验证**（`collision_shape` / `generation` / `depth` / `marker_changed`），
   使成功判定不依赖运气。

第 5 点尤其重要：现有 `chain_hits` 只在 `*verify == value` 时置位，等于「
读回自己的写」，无法区分「写到了目标」与「写到了旁边」。`preload.so` 用
`marker`/`generation` 做独立验证，正是为了避免这一点。

## 下一步

这是一条 **L 级**（攻击关键路径）改动，按 `AGENTS.md` 需先出计划文档并获认可再动代码。
建议顺序：

1. **反汇编 `preload.so` 的 `reclaim_race`**，用格式串交叉引用定位函数边界，
   把上表第 1-5 点从「字符串推断」升级为「指令级事实」。
2. 依据反汇编结果产出实施计划（含所有权/生命周期审查，因为要在管道槽与
   slab 对象之间建立新的持有关系）。
3. 实现后重跑本门禁；**必须冷启动**，且按 `AGENTS.md` 需要同构建复现来判定因果。

在第 1 步完成前，不建议改动 `fd_graph_route.cpp`：现有实现虽然无效，但其
`prepare/execute/disarm/destroy` 形状与 12 个常量是重写时的对照基准。