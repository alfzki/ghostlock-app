/* Host test for the ancillary controller: the behavior registry, the profile
 * gate, the dispatch signature, and the vr.ko plan (fixed vectors). */

#include "session/ancillary/ancillary_controller.hpp"

#include <cassert>
#include <concepts>
#include <cstdio>
#include <tuple>

using namespace ghostlock;

namespace ghostlock::profile {
    /* Test-binary definition of the startup-read-only profile global. The
     * production definition lives in attack/ops.cpp next to its only writer
     * (main), which the host test does not link. */
    vr_guard_layout g_vr_guard_layout{};
}

namespace {
    struct EmptyMiddleware final {};

    /* A behavior that opts in, to exercise the enabled-traversal independent of
     * the registered VrGuardPolicy. */
    struct OnPolicy : session::ancillary::AncillaryPolicyDefaults {
        static constexpr session::ancillary::AncillaryKind kind =
                session::ancillary::AncillaryKind::VrGuard;

        static bool enabled(const profile::TargetProfile &) noexcept {
            return true;
        }
    };

    constexpr uintptr_t kChildTask = 0xffff8000'0000'1000;

    void set_vr_gate(bool on) {
        profile::g_vr_guard_layout.enabled = on ? 1 : 0;
    }
} // namespace

int main() {
    using namespace session::ancillary;

    /* Both the registered behavior and an opting-in one satisfy the contract. */
    static_assert(AncillaryPolicyFor<VrGuardPolicy, EmptyMiddleware>);
    static_assert(AncillaryPolicyFor<OnPolicy, EmptyMiddleware>);

    /* The registry currently holds exactly the vr.ko guard. */
    static_assert(std::tuple_size_v<AncillaryPolicyList> == 1);

    int visited = 0;
    bool saw_vr_guard = false;
    for_each_ancillary_policy([&]<class P>() {
        ++visited;
        if (P::kind == AncillaryKind::VrGuard) saw_vr_guard = true;
    });
    assert(visited == 1 && saw_vr_guard);

    /* An absent gate field fails closed: no behavior is reached. */
    profile::g_vr_guard_layout = {};
    const profile::TargetProfile empty_profile{};
    assert(!VrGuardPolicy::enabled(empty_profile));
    int enabled_visited = 0;
    for_each_enabled_ancillary_policy(empty_profile, [&]<class P>() { ++enabled_visited; });
    assert(enabled_visited == 0);

    /* A gate field of 0 also fails closed (present but disabled). */
    set_vr_gate(false);
    assert(!VrGuardPolicy::enabled(empty_profile));

    /* Gate set: the behavior is reached by the same traversal. */
    set_vr_gate(true);
    assert(VrGuardPolicy::enabled(empty_profile));
    enabled_visited = 0;
    for_each_enabled_ancillary_policy(empty_profile, [&]<class P>() { ++enabled_visited; });
    assert(enabled_visited == 1);

    /* An opting-in behavior is reached regardless of the vr.ko gate. */
    set_vr_gate(false);
    assert(OnPolicy::enabled(empty_profile));

    /* ---- vr.ko plan: fixed vectors ---- */

    /* Word alignment: the primitive stores whole 8-byte words, so a byte-granular
     * field is cleared via the word that contains it. */
    static_assert(vr_align_down_word(0x1000 + 0x2c) == 0x1000 + 0x28);
    static_assert(vr_align_down_word(0x1000 + 0x27) == 0x1000 + 0x20);
    static_assert(vr_align_down_word(0x1000) == 0x1000);

    /* Probe plan: 6.1 layout (funcs at +0x40). */
    constexpr uintptr_t kTp = 0xffff8000'000a'0000;
    const auto probe = vr_plan_probe(0x40, kTp);
    assert(probe.has_value());
    assert(probe->target == kTp + 0x40);

    /* Probe plan: 6.6 layout (funcs at +0x48) is a different target, never
     * inferred from the release string. */
    const auto probe66 = vr_plan_probe(0x48, kTp);
    assert(probe66.has_value() && probe66->target == kTp + 0x48);

    /* Fail closed: no funcs_offset in the profile, or no resolved symbol. */
    assert(!vr_plan_probe(std::nullopt, kTp).has_value());
    assert(!vr_plan_probe(0x40, 0).has_value());

    /* Tag plan: the thread_info flags word always, tag B when configured. */
    const VrTagPlan tags = vr_plan_tags(0x2c, kChildTask);
    assert(tags.flags.target == kChildTask + kernel::TASK_THREAD_INFO_FLAGS_OFF);
    assert(tags.tag_b.has_value());
    assert(tags.tag_b->target == ((kChildTask + 0x2c) & ~static_cast<uintptr_t>(7)));

    /* A provided tag_b_off of 0 is a real offset, not "absent". */
    const VrTagPlan zero_tag = vr_plan_tags(0, kChildTask);
    assert(zero_tag.tag_b.has_value() && zero_tag.tag_b->target == kChildTask);

    /* Without tag_b_off only the flags word is written. */
    const VrTagPlan no_tag = vr_plan_tags(std::nullopt, kChildTask);
    assert(!no_tag.tag_b.has_value());
    assert(no_tag.flags.target == kChildTask + kernel::TASK_THREAD_INFO_FLAGS_OFF);

    /* The documented tagging scheme: tag A and the syscall-tracepoint bit both
     * live inside the word the plan zeroes. */
    static_assert(VR_TAG_A_OFF == 0x06);
    static_assert(VR_SYSCALL_TP_FLAG == 0x400);
    static_assert(VR_TAG_A_OFF < sizeof(uintptr_t));
    static_assert(VR_TAG_A_OFF >= 1);

    /* The controller exposes the stage entry the backend calls. */
    static_assert(
        requires(session::ExploitSession &session, AncillaryContext &context) {
            {
                AncillaryController<EmptyMiddleware>::apply(
                    AncillaryStage::PreSpawn, session, context)
            } -> std::same_as<Status>;
        });

    /* The context fails closed: nothing is injected unless the caller provides
     * the capability. */
    AncillaryContext context{};
    assert(!context.write_available);
    assert(!context.component_present);
    assert(context.child_task == 0);

    puts("ancillary_test: ok");
    return 0;
}