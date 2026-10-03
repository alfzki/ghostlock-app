package com.ghostlock.app.data.route

/**
 * `route.fd_graph` section. Mirrors native `FdGraphLayout` (KernelMisc fields).
 * Every field is optional: absence means "not provided".
 */
data class FdGraphConfig(
    val eventpollSize: UInt?,
    val epitemEp: UInt?,
    val epitemFllink: UInt?,
    val pipeBuffer: UInt?,
    val pipeFlags: UInt?,
    val pipeSlots: UInt?,
    val pipeRing: UInt?,
    val pipeObject: UInt?,
    val graphWidth: UInt?,
    val graphFanout: UInt?,
    val graphEdges: UInt?,
    val objectsPerOrder3: UInt?,
) : RouteConfig {
    override fun entries(): List<Pair<String, ULong>> = buildList {
        eventpollSize?.let { add("eventpoll_size" to it.toULong()) }
        epitemEp?.let { add("epitem_ep" to it.toULong()) }
        epitemFllink?.let { add("epitem_fllink" to it.toULong()) }
        pipeBuffer?.let { add("pipe_buffer" to it.toULong()) }
        pipeFlags?.let { add("pipe_flags" to it.toULong()) }
        pipeSlots?.let { add("pipe_slots" to it.toULong()) }
        pipeRing?.let { add("pipe_ring" to it.toULong()) }
        pipeObject?.let { add("pipe_object" to it.toULong()) }
        graphWidth?.let { add("graph_width" to it.toULong()) }
        graphFanout?.let { add("graph_fanout" to it.toULong()) }
        graphEdges?.let { add("graph_edges" to it.toULong()) }
        objectsPerOrder3?.let { add("objects_per_order3" to it.toULong()) }
    }

    override fun apply(key: String, value: ULong): RouteConfig = when (key) {
        "eventpoll_size" -> copy(eventpollSize = value.toUInt())
        "epitem_ep" -> copy(epitemEp = value.toUInt())
        "epitem_fllink" -> copy(epitemFllink = value.toUInt())
        "pipe_buffer" -> copy(pipeBuffer = value.toUInt())
        "pipe_flags" -> copy(pipeFlags = value.toUInt())
        "pipe_slots" -> copy(pipeSlots = value.toUInt())
        "pipe_ring" -> copy(pipeRing = value.toUInt())
        "pipe_object" -> copy(pipeObject = value.toUInt())
        "graph_width" -> copy(graphWidth = value.toUInt())
        "graph_fanout" -> copy(graphFanout = value.toUInt())
        "graph_edges" -> copy(graphEdges = value.toUInt())
        "objects_per_order3" -> copy(objectsPerOrder3 = value.toUInt())
        else -> this
    }

    companion object {
        val EMPTY = FdGraphConfig(null, null, null, null, null, null, null, null, null, null, null, null)

        /* Prefixes are load-bearing: ProfileResolver.nativeValue only rewrites a route
         * field for a path carrying this route's name. Do not strip them. */
        fun from(value: (String) -> Long?): FdGraphConfig = FdGraphConfig(
            eventpollSize = value("fd_graph.eventpoll_size")?.toUInt(),
            epitemEp = value("fd_graph.epitem_ep")?.toUInt(),
            epitemFllink = value("fd_graph.epitem_fllink")?.toUInt(),
            pipeBuffer = value("fd_graph.pipe_buffer")?.toUInt(),
            pipeFlags = value("fd_graph.pipe_flags")?.toUInt(),
            pipeSlots = value("fd_graph.pipe_slots")?.toUInt(),
            pipeRing = value("fd_graph.pipe_ring")?.toUInt(),
            pipeObject = value("fd_graph.pipe_object")?.toUInt(),
            graphWidth = value("fd_graph.graph_width")?.toUInt(),
            graphFanout = value("fd_graph.graph_fanout")?.toUInt(),
            graphEdges = value("fd_graph.graph_edges")?.toUInt(),
            objectsPerOrder3 = value("fd_graph.objects_per_order3")?.toUInt(),
        )
    }
}