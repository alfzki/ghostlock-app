#ifndef GHOSTLOCK_ANCILLARY_POLICY_HPP
#define GHOSTLOCK_ANCILLARY_POLICY_HPP

#include <concepts>
#include <cstdint>

#include "profile/model.h"
#include "support/status.hpp"

namespace ghostlock::session {
    struct ExploitSession;
}

namespace ghostlock::session::ancillary {
    /* Stable ancillary-behavior ids. Explicit numeric values; never rely on the
     * compiler's enum layout. VrGuard is the first and currently the only
     * behavior; a new behavior appends an id here and a policy to the registry. */
    enum class AncillaryKind : std::uint8_t {
        VrGuard = 1,
    };

    /* When the controller runs a behavior, relative to the backend attack steps:
     *   PreSpawn   - W1 done, before the victim is spawned;
     *   PostSpawn  - the rooted child exists (today's W2b);
     *   PreHandoff - before the frontend handoff. */
    enum class AncillaryStage : std::uint8_t {
        PreSpawn = 0,
        PostSpawn = 1,
        PreHandoff = 2,
    };

    /* Capabilities a behavior needs from the backend: the write primitive, the
     * stage-R read-back, the address of the task the behavior must protect, and
     * the runtime applicability decision (guide section 5). Injected at the call
     * site so this header stays host-compilable; every flag defaults to false so
     * a caller that does not inject a capability fails closed. */
    struct AncillaryContext {
        bool write_available = false;
        bool read_available = false;
        /* Whether the vendor component a behavior targets is actually loaded.
         * The profile gate is only a pre-set: the same GKI release ships from
         * several vendors, so a behavior records its runtime decision here and
         * does nothing when the component is absent. */
        bool component_present = false;
        uintptr_t child_task = 0;
    };

    /* Neutral defaults so the controller can walk every registered behavior. A
     * behavior that is off reports false; an empty apply is a no-op success. */
    struct AncillaryPolicyDefaults {
        static bool enabled(const profile::TargetProfile &) noexcept {
            return false;
        }

        template <class Middleware>
        static Status apply(AncillaryStage, ExploitSession &, AncillaryContext &) noexcept {
            return true;
        }
    };

    /* Ancillary-behavior contract. `kind` names the behavior, `enabled` gates it
     * from the resolved profile, and `apply<Middleware>` is the stage entry. The
     * write primitive depends on the middleware, so apply is templated like the
     * backend's steps. */
    template <class P, class Middleware>
    concept AncillaryPolicyFor = requires(const profile::TargetProfile &profile,
                                          ExploitSession &session,
                                          AncillaryContext &context) {
        { P::kind } -> std::convertible_to<AncillaryKind>;
        { P::enabled(profile) } -> std::same_as<bool>;
        { P::template apply<Middleware>(AncillaryStage::PreSpawn, session, context) }
            -> std::same_as<Status>;
    };
} // namespace ghostlock::session::ancillary

#endif
