#include "route/fd_graph_route.h"

#include <cassert>
#include <cstdint>
#include <type_traits>
#include <unistd.h>
#include <fcntl.h>

using namespace ghostlock;

int32_t main(void) {
    ghostlock::memory::WriteRequest request{};
    ghostlock::profile::FdGraphLayout layout = {
        .eventpoll_size = 0xd0,
        .epitem_ep = 0x48,
        .epitem_fllink = 0x50,
        .pipe_buffer = 0x28,
        .pipe_flags = 0x18,
        .pipe_slots = 0x20,
        .pipe_ring = 0x500,
        .pipe_object = 0x800,
        .graph_width = 96,
        .graph_fanout = 256,
        .graph_edges = 24576,
        .objects_per_order3 = 16,
    };
    const profile::TargetProfile profile{};

    ghostlock::route::fd_graph::FdGraphRoute context(&request, profile, layout);
    assert(context.request == &request);
    assert(&context.profile == &profile);
    assert(context.layout.eventpoll_size.value_or(0) == 0xd0);
    assert(context.layout.epitem_ep.value_or(0) == 0x48);
    assert(context.layout.epitem_fllink.value_or(0) == 0x50);
    assert(context.layout.pipe_buffer.value_or(0) == 0x28);
    assert(context.layout.pipe_flags.value_or(0) == 0x18);
    assert(context.layout.pipe_slots.value_or(0) == 0x20);
    assert(context.layout.pipe_ring.value_or(0) == 0x500);
    assert(context.layout.pipe_object.value_or(0) == 0x800);
    assert(context.layout.graph_width.value_or(0) == 96);
    assert(context.layout.graph_fanout.value_or(0) == 256);
    assert(context.layout.graph_edges.value_or(0) == 24576);
    assert(context.layout.objects_per_order3.value_or(0) == 16);
    assert(!context.epoll_fd.valid() && !context.pipe_read.valid());
    assert(!context.pipe_write.valid() && !context.consumer_thread.joinable());
    assert(context.consumer_stuck == 0);
    assert(context.status.code == ghostlock::route::ROUTE_RETRYABLE);

    /* Move-only: no copy, descriptors transfer with the move. */
    static_assert(!std::is_copy_constructible_v<ghostlock::route::fd_graph::FdGraphRoute>);
    static_assert(!std::is_copy_assignable_v<ghostlock::route::fd_graph::FdGraphRoute>);
    static_assert(std::is_move_constructible_v<ghostlock::route::fd_graph::FdGraphRoute>);
    {
        ghostlock::route::fd_graph::FdGraphRoute source(&request, profile, layout);
        int32_t fds[2];
        assert(pipe(fds) == 0);
        source.pipe_read.reset(fds[0]);
        source.pipe_write.reset(fds[1]);
        ghostlock::route::fd_graph::FdGraphRoute moved(std::move(source));
        assert(moved.pipe_read.get() == fds[0]);
        assert(!source.pipe_read.valid());
        assert(moved.pipe_write.get() == fds[1]);
        moved.destroy();
        assert(!moved.pipe_read.valid() && !moved.pipe_write.valid());
        assert(fcntl(fds[0], F_GETFD) == -1 && errno == EBADF);
        assert(fcntl(fds[1], F_GETFD) == -1 && errno == EBADF);
    }

    /* fail() records step and errno for the caller's log. */
    assert(context.fail(59, 5) == -1);
    assert(context.status.step == 59);
    assert(context.status.error_number == 5);

    /* disarm is idempotent and marks the route disarmed. */
    context.disarm();
    context.disarm();
    assert(context.status.kernel_disarmed == 1);

    /* destroy without resources is idempotent and reports a clean fallback. */
    context.destroy();
    context.destroy();
    assert(context.status.userspace_clean == 1);
    assert(context.status.code == ghostlock::route::ROUTE_FALLBACK_SAFE);

    puts("fd_graph_route_test: ok");
    return 0;
}