# W1 PI race rework — CMP_REQUEUE_PI returns EDEADLK (2026-10-04)

## 现状与基线
HEAD: eab8079 (revert of val3 experiment).
Baseline binary `build/native/ghostlock` sha256 is whatever `git rev-parse` reports; `PROFILE-61258-04` archived the val3-specific run.

Observed steady state on every device run (batch A and otherwise):
`[route] CMP_REQUEUE_PI ret=-1 errno=35` (`EDEADLK`, not EAGAIN).
Call site: `src/core/race/threads.cpp:182` → `support::futex_op` is a direct pass-through.

Race threads (`threads.cpp`):
- `waiter_thread`: `FUTEX_LOCK_PI chain_futex`(:24) → `waiter_ready=1`(:26) → wait `owner_started`(:27) → `FUTEX_WAIT_REQUEUE_PI(wait_futex, val=0, &timeout, &target_futex)`(:48) → wait for route_done.
- `owner_thread`: `FUTEX_LOCK_PI target_futex`(:78) → wait `waiter_ready`(:81) → `owner_started=1`(:89) → `FUTEX_LOCK_PI chain_futex`(:90) → unlock target(:94).
- `PiRace::run`: wait `waiter_waiting && owner_started`(:175) → `FUTEX_CMP_REQUEUE_PI(wait_futex, nr_wake=1, nr_requeue=1, &target_futex, val3)`(:182).

## 目标与约束
Goal: make the W1 PI-futex race window actually establish (CMP_REQUEUE_PI succeeds), so that the `fd_graph` route has a contended `target_futex` to exploit. Non-goals: batch D remains frozen; no profile/wire format change; no `fd_graph_route.cpp` edit; no removal of the existing hill (this plan does not delete the val3== val matching that eab8079 restored). Constraint: any code change to threads.cpp is an L-level attack-path change, gated by `cmp_disasm`, NDK zero-warning, host tests, lint-tidy, cold-boot device gate, archive.

## Hypothesis register (must be disambiguated before any production change)
H1 (primary): `owner_thread` pre-holds `target_futex` at line 78, so requeuing the waiter onto `target_futex` forms a PI cycle and the kernel returns `EDEADLK`.
H2 (competing): the waiter is never actually parked on `wait_futex` when CMP_REQUEUE_PI runs (e.g. it timed out or the wait was on the wrong word), so the requeue finds no waiters and the error path differs.
H3: `val3` mismatch would fail *before* EDEADLK could be observed — currently ruled out because `errno` reached EDEADLK (35), which is produced after the value comparison succeeds.

## Why certainty is required before Wave 1
Previous turn, the val3=1 "fix" was applied, then reverted after the explore agent showed `wait_futex` is never set to 1. That change was made on the basis of an assumption about H3, not evidence. This plan therefore makes the FIRST deliverable a decisive measurement, not a guess.

## Wave 0 — decisive diagnostic (no production code change expected)
Objective: distinguish H1 vs H2 vs neither.
- Add a temporary `-DLOG` style log line (or use existing `pr_info`) in `waiter_thread` after line 48 reporting the return of `FUTEX_WAIT_REQUEUE_PI` and its `errno`, and in `PiRace::run` after line 182 reporting current `wait_futex`/`owner_started`/`waiter_waiting`. This is diagnostics only and is reverted in Wave N unless adopted.
- Cold-boot device gate: one run, capture the exact errno/return of the WAIT and the CMP.
- Read: if WAIT on line 48 already returned with an error or timed out before CMP runs, H2 is confirmed and the fix is in the WAIT timeout/waiter_parking, not the CMP. If WAIT succeeded and CMP still returns EDEADLK while owner holds target_futex, H1 is favored.

## Wave 1 — candidate fix (only if Wave 0 implies it)
If H1: restructure the owner so it does NOT hold `target_futex` while requeue is pending. Options:
  (a) owner blocks acquiring `target_futex` only AFTER CMP_REQUEUE_PI has moved the waiter (reorder :78 to after :182), or
  (b) owner waits on a futex independent of `target_futex` until the requeue is acknowledged.
If H2: fix the waiter park (correct timeout / correct word / correct requeue target).
Each branch gets its own sub-plan + `cmp_disasm` + device gate.

## Wave 2 — verify
Same gate matrix as every attack-path change; the success artifact is a device log line showing `CMP_REQUEUE_PI ret>=0` and no kernel panic, archived as `PROFILE-61258-0N`.

## 明确保留 / 回滚
No retcon of gate archives 01–04; this plan builds on them. Rollback = `git revert` the Wave-1 commit only.

## 进度
- [x] facts recorded, notepad updated
- [ ] Wave 0: instrument + one cold-boot run, capture WAIT and CMP errnos
- [ ] disambiguate H1/H2/H3
- [ ] Wave 1: sub-plan per outcome, implement, disasm gate, device gate
- [ ] archive
