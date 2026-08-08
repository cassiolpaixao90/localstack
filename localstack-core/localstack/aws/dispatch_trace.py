"""Opt-in, request-confined tracing of AWS implementation dispatch origins."""

from typing import Any, TypedDict


class DispatchTraceEntry(TypedDict):
    origin: str
    handler: str
    outcome: str


DispatchTrace = list[DispatchTraceEntry]
DISPATCH_TRACE_CONTEXT_KEY = "_localstack_dispatch_trace"


def get_dispatch_trace(context: Any) -> DispatchTrace | None:
    try:
        return context.__dict__.get(DISPATCH_TRACE_CONTEXT_KEY)
    except AttributeError:
        return getattr(context, DISPATCH_TRACE_CONTEXT_KEY, None)


def enable_dispatch_trace(context: Any) -> DispatchTrace:
    """Enable implementation-origin tracing and return the request-local trace."""

    trace = get_dispatch_trace(context)
    if trace is None:
        trace = []
        setattr(context, DISPATCH_TRACE_CONTEXT_KEY, trace)
    return trace


def share_dispatch_trace(source: Any, target: Any) -> None:
    """Share an enabled trace with a rewritten context for the same request."""

    if (trace := get_dispatch_trace(source)) is not None:
        setattr(target, DISPATCH_TRACE_CONTEXT_KEY, trace)


def start_dispatch(
    context: Any,
    origin: str,
    handler: str,
    deduplicate_active_origin: bool = False,
) -> int | None:
    """Start a trace entry and return the index used to complete it."""

    trace = get_dispatch_trace(context)
    if trace is None:
        return None
    if (
        deduplicate_active_origin
        and trace
        and trace[-1]["origin"] == origin
        and trace[-1]["outcome"] == "started"
    ):
        return None

    trace.append({"origin": origin, "handler": handler, "outcome": "started"})
    return len(trace) - 1


def finish_dispatch(context: Any, index: int | None, outcome: str) -> None:
    """Complete a trace entry previously created by :func:`start_dispatch`."""

    if index is not None and (trace := get_dispatch_trace(context)) is not None:
        trace[index]["outcome"] = outcome
