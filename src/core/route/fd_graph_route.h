#ifndef FD_GRAPH_ROUTE_H
#define FD_GRAPH_ROUTE_H

#include "memory/payload_builder.h"
#include "profile/model.h"
#include "route/route_status.h"
#include "support/native_resource.hpp"

namespace ghostlock::route::fd_graph {

class FdGraphRoute final {
public:
    FdGraphRoute(const ghostlock::memory::WriteRequest *route_request,
                 const ghostlock::profile::TargetProfile &profile_value,
                 ghostlock::profile::FdGraphLayout route_layout) noexcept;

    ~FdGraphRoute() noexcept = default;

    FdGraphRoute(const FdGraphRoute &) = delete;
    FdGraphRoute &operator=(const FdGraphRoute &) = delete;

    FdGraphRoute(FdGraphRoute &&other) noexcept;

    [[nodiscard]] int32_t prepare() noexcept;

    [[nodiscard]] ghostlock::route::RouteStatus execute() noexcept;

    void disarm() noexcept;

    void destroy() noexcept;

    [[nodiscard]] int32_t fail(int32_t step, int32_t error_number) noexcept;

    const ghostlock::memory::WriteRequest *request = nullptr;
    const ghostlock::profile::TargetProfile &profile;
    ghostlock::profile::FdGraphLayout layout{};
    ghostlock::support::UniqueFd epoll_fd;
    ghostlock::support::UniqueFd pipe_read;
    ghostlock::support::UniqueFd pipe_write;
    ghostlock::support::PthreadOwner consumer_thread;
    int32_t consumer_stuck = 0;
    int32_t calls = 0;
    int32_t successes = 0;
    ghostlock::route::RouteStatus status{};

private:
    void retain_for_process_lifetime() noexcept;
};

// Entry point called by FdGraphPolicy::run()
ghostlock::route::RouteStatus do_fd_graph_fake_lock_route(const ghostlock::memory::WriteRequest *request);

} // namespace ghostlock::route::fd_graph

#endif