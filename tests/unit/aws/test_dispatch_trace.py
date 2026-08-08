from types import SimpleNamespace

import pytest

from localstack.aws.api import CommonServiceException, RequestContext, handler
from localstack.aws.chain import HandlerChain
from localstack.aws.dispatch_trace import (
    enable_dispatch_trace,
    finish_dispatch,
    get_dispatch_trace,
    start_dispatch,
)
from localstack.aws.forwarder import ForwardingFallbackDispatcher
from localstack.aws.handlers.metric_handler import Metric, MetricHandler
from localstack.aws.handlers.service import ServiceRequestRouter
from localstack.aws.skeleton import ServiceRequestDispatcher, create_dispatch_table
from localstack.aws.spec import load_service
from localstack.http import Response
from localstack.services import moto


class GeneratedApi:
    __module__ = "localstack.aws.api.sample"

    @handler("DoThing")
    def do_thing(self, context, **kwargs):
        raise NotImplementedError


class NativeProvider(GeneratedApi):
    __module__ = "localstack.services.sample.provider"

    def do_thing(self, context, **kwargs):
        return {"result": "native"}


def _traced_context() -> RequestContext:
    context = RequestContext(None)
    enable_dispatch_trace(context)
    return context


def test_disabled_trace_does_not_invoke_context_getattr():
    class MutableContext:
        def __getattr__(self, _name):
            raise AssertionError("missing-attribute lookup reached")

    assert get_dispatch_trace(MutableContext()) is None


def test_dispatch_trace_records_native_handler():
    context = _traced_context()
    dispatch = create_dispatch_table(NativeProvider())

    result = dispatch["DoThing"](context, {})

    assert result == {"result": "native"}
    assert get_dispatch_trace(context) == [
        {
            "origin": "native",
            "handler": "localstack.services.sample.provider.NativeProvider.do_thing",
            "outcome": "returned",
        }
    ]


def test_dispatch_trace_records_generated_stub_and_moto_fallback():
    context = _traced_context()

    def fallback(_context, _request):
        return {"result": "moto"}

    dispatch = ForwardingFallbackDispatcher(GeneratedApi(), fallback, fallback_origin="moto")

    result = dispatch["DoThing"](context, {})

    assert result == {"result": "moto"}
    assert get_dispatch_trace(context) == [
        {
            "origin": "generated-stub",
            "handler": "localstack.aws.api.sample.GeneratedApi.do_thing",
            "outcome": "not-implemented",
        },
        {
            "origin": "delegated:moto",
            "handler": "fallback",
            "outcome": "returned",
        },
    ]


def test_dispatch_trace_records_handler_error():
    class FailingProvider(GeneratedApi):
        __module__ = "localstack.services.sample.provider"

        def do_thing(self, context, **kwargs):
            raise ValueError("boom")

    context = _traced_context()
    dispatch = create_dispatch_table(FailingProvider())

    try:
        dispatch["DoThing"](context, {})
    except ValueError:
        pass

    assert get_dispatch_trace(context) == [
        {
            "origin": "native",
            "handler": "localstack.services.sample.provider.FailingProvider.do_thing",
            "outcome": "error",
        }
    ]


def test_dispatch_trace_distinguishes_expected_service_exception():
    class ValidatingProvider(GeneratedApi):
        __module__ = "localstack.services.sample.provider"

        def do_thing(self, context, **kwargs):
            raise CommonServiceException("ValidationException", "invalid")

    context = _traced_context()
    dispatch = create_dispatch_table(ValidatingProvider())

    with pytest.raises(CommonServiceException):
        dispatch["DoThing"](context, {})

    assert get_dispatch_trace(context)[-1]["outcome"] == "service-exception"


def test_dispatch_trace_finishes_when_handler_is_cancelled():
    class CancelledProvider(GeneratedApi):
        __module__ = "localstack.services.sample.provider"

        def do_thing(self, context, **kwargs):
            raise KeyboardInterrupt

    context = _traced_context()
    dispatch = create_dispatch_table(CancelledProvider())

    with pytest.raises(KeyboardInterrupt):
        dispatch["DoThing"](context, {})

    assert get_dispatch_trace(context)[-1]["outcome"] == "error"


def test_direct_dispatcher_uses_neutral_origin():
    context = _traced_context()
    dispatcher = ServiceRequestDispatcher(lambda **_kwargs: {}, "DoThing", pass_context=False)

    dispatcher(context, {})

    assert get_dispatch_trace(context)[-1]["origin"] == "unknown"


def test_dispatch_skips_trace_hooks_when_tracing_is_disabled(monkeypatch):
    context = RequestContext(None)
    dispatch = create_dispatch_table(NativeProvider())
    monkeypatch.setattr(
        "localstack.aws.skeleton.start_dispatch",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("trace hook called")),
    )

    assert dispatch["DoThing"](context, {}) == {"result": "native"}


def test_service_request_router_records_missing_operation(monkeypatch):
    context = _traced_context()
    context.service = load_service("sqs")
    context.operation = context.service.operation_model("SendMessage")
    router = ServiceRequestRouter()
    monkeypatch.setattr(
        router,
        "create_not_implemented_response",
        lambda _context: Response(status=501),
    )
    chain = HandlerChain([router])

    chain.handle(context, Response())

    assert get_dispatch_trace(context) == [
        {"origin": "none", "handler": "service-request-router", "outcome": "missing"}
    ]


def test_metric_serializes_dispatch_trace():
    dispatch_trace = '[{"origin":"native","handler":"provider.call","outcome":"returned"}]'

    metric = Metric(
        service="sample",
        operation="DoThing",
        headers="",
        parameters="",
        response_code=200,
        response_data="",
        exception="",
        origin="external",
        dispatch_trace=dispatch_trace,
    )

    assert Metric.RAW_DATA_HEADER[-1] == "dispatch_trace"
    assert list(metric)[-1] == dispatch_trace


def test_direct_moto_call_records_delegated_origin(monkeypatch):
    context = _traced_context()
    monkeypatch.setattr(
        moto,
        "dispatch_to_backend",
        lambda _context, _dispatcher, _include_metadata: {"result": "moto"},
    )

    result = moto.call_moto(context)

    assert result == {"result": "moto"}
    assert get_dispatch_trace(context) == [
        {
            "origin": "delegated:moto",
            "handler": "call_moto",
            "outcome": "returned",
        }
    ]


def test_moto_call_reuses_active_fallback_trace(monkeypatch):
    context = _traced_context()
    trace_index = start_dispatch(context, "delegated:moto", "_proxy_moto")
    monkeypatch.setattr(
        moto,
        "dispatch_to_backend",
        lambda _context, _dispatcher, _include_metadata: {"result": "moto"},
    )

    moto.call_moto(context)
    finish_dispatch(context, trace_index, "returned")

    assert get_dispatch_trace(context) == [
        {
            "origin": "delegated:moto",
            "handler": "_proxy_moto",
            "outcome": "returned",
        }
    ]


def test_moto_request_rewrite_preserves_original_dispatch_trace(monkeypatch):
    original_context = SimpleNamespace(
        service=SimpleNamespace(service_name="sample"),
        operation=SimpleNamespace(name="DoThing"),
        region="us-east-1",
        protocol="json",
        request=SimpleNamespace(headers={}),
    )
    original_trace = enable_dispatch_trace(original_context)
    rewritten_context = RequestContext(None)
    rewritten_context.request = SimpleNamespace(headers={})
    monkeypatch.setattr(moto, "create_aws_request_context", lambda **_kwargs: rewritten_context)
    monkeypatch.setattr(
        moto,
        "call_moto",
        lambda context: {"same": get_dispatch_trace(context) is original_trace},
    )

    result = moto.call_moto_with_request(original_context, {})

    assert result == {"same": True}


def test_metric_collection_enables_dispatch_trace(monkeypatch):
    context = RequestContext(None)
    metric_handler = MetricHandler()
    monkeypatch.setattr("localstack.config.is_collect_metrics_mode", lambda: True)

    metric_handler.create_metric_handler_item(None, context, None)

    assert get_dispatch_trace(context) == []


def test_metric_collection_cleans_up_unparsed_request(monkeypatch):
    context = RequestContext(None)
    monkeypatch.setattr("localstack.config.is_collect_metrics_mode", lambda: True)
    monkeypatch.setattr("localstack.config.store_test_metrics_in_local_filesystem", lambda: False)
    metric_handler = MetricHandler()
    metric_handler.create_metric_handler_item(None, context, None)

    metric_handler.update_metric_collection(None, context, Response())

    assert context not in metric_handler.metrics_handler_items


def test_metric_collection_cleans_up_when_metrics_mode_changes(monkeypatch):
    context = RequestContext(None)
    enabled = True
    monkeypatch.setattr("localstack.config.is_collect_metrics_mode", lambda: enabled)
    monkeypatch.setattr("localstack.config.store_test_metrics_in_local_filesystem", lambda: False)
    metric_handler = MetricHandler()
    metric_handler.create_metric_handler_item(None, context, None)
    enabled = False

    metric_handler.update_metric_collection(None, context, Response())

    assert context not in metric_handler.metrics_handler_items
