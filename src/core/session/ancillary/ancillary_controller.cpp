/*
 * GhostLock — ancillary controller translation unit.
 *
 * Forces the controller header through the Android compile (and clang-tidy) so
 * the host-safe interface cannot drift from what the device build sees, and
 * pins the controller's instantiations to the catalogued middleware policies.
 * The dispatcher itself never changes when a behavior is added, so this list is
 * the only place the backend's stage calls meet the behavior's write primitive.
 */

#include "session/ancillary/ancillary_controller.hpp"

#include "route/route_policy.hpp"

namespace ghostlock::session::ancillary {
    template Status AncillaryController<route::SelectPolicy>::apply(
        AncillaryStage, ExploitSession &, AncillaryContext &);
    template Status AncillaryController<route::TcpPolicy>::apply(
        AncillaryStage, ExploitSession &, AncillaryContext &);
    template Status AncillaryController<route::MulticastPolicy>::apply(
        AncillaryStage, ExploitSession &, AncillaryContext &);
} // namespace ghostlock::session::ancillary