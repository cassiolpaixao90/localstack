import logging
import os
import sys
from pathlib import Path

import yaml
from plux import Plugin

from localstack import config
from localstack.runtime import hooks
from localstack.utils.files import rm_rf
from localstack.utils.ssl import get_cert_pem_file_path

LOG = logging.getLogger(__name__)


def _native_snapshot_load_enabled() -> bool:
    return config.PERSISTENCE and config.SNAPSHOT_LOAD_STRATEGY in {"", "ON_STARTUP"}


def _native_snapshot_save_enabled() -> bool:
    # This persistence subset has no on-request implementation. Unsupported strategies stay off.
    return config.PERSISTENCE and config.SNAPSHOT_SAVE_STRATEGY in {"", "ON_SHUTDOWN"}


@hooks.on_infra_start(priority=200, should_load=_native_snapshot_load_enabled)
def load_native_service_snapshots() -> None:
    from localstack.state.service_persistence import (
        load_service_snapshots,
        native_service_stores,
    )

    load_service_snapshots(config.dirs.data, native_service_stores())
    from localstack.services.apigateway.next_gen.execute_api.router import (
        get_api_gateway_router,
    )

    router = get_api_gateway_router()
    router.register_routes()
    router.sync_custom_domains()

    _repair_restored_lambda_state()
    _fail_in_progress_cloudformation_stacks()
    _reset_restored_sqs_queues()


def _repair_restored_lambda_state() -> None:
    """Re-create in-process version managers for restored functions.

    Restored function versions are Active in the store but have no version manager in the
    process-local registry, so invokes would fail with ResourceConflictException. The repair
    waits at most 5s per version and logs failures instead of raising, so startup cannot hang.
    """
    from localstack.services.lambda_.invocation.models import lambda_stores

    if not lambda_stores:
        return

    from localstack.services.lambda_.provider import LambdaProvider
    from localstack.services.plugins import SERVICE_PLUGINS

    container = SERVICE_PLUGINS.get_service_container("lambda")
    provider = getattr(container.service, "_provider", None) if container else None
    if not isinstance(provider, LambdaProvider):
        LOG.warning("Unable to repair restored Lambda state: lambda provider is unavailable")
        return
    provider.on_after_state_load()


# Terminal statuses for stacks interrupted mid-operation by a shutdown. On AWS an interrupted
# update or import rolls back; LocalStack cannot resume the rollback after a restart, so those
# stacks land in the rollback-failed terminal state. Interrupted creates and deletes fail
# outright. REVIEW_IN_PROGRESS is a stable user-waiting state, not an in-flight operation.
_IN_PROGRESS_STACK_TERMINALS = {
    "CREATE_IN_PROGRESS": "CREATE_FAILED",
    "ROLLBACK_IN_PROGRESS": "ROLLBACK_FAILED",
    "DELETE_IN_PROGRESS": "DELETE_FAILED",
    "UPDATE_IN_PROGRESS": "UPDATE_ROLLBACK_FAILED",
    "UPDATE_COMPLETE_CLEANUP_IN_PROGRESS": "UPDATE_ROLLBACK_FAILED",
    "UPDATE_ROLLBACK_IN_PROGRESS": "UPDATE_ROLLBACK_FAILED",
    "UPDATE_ROLLBACK_COMPLETE_CLEANUP_IN_PROGRESS": "UPDATE_ROLLBACK_FAILED",
    "IMPORT_IN_PROGRESS": "IMPORT_ROLLBACK_FAILED",
    "IMPORT_ROLLBACK_IN_PROGRESS": "IMPORT_ROLLBACK_FAILED",
}
_STACK_RESTART_REASON = "LocalStack restarted while the stack operation was in progress"


def _fail_in_progress_cloudformation_stacks() -> None:
    from localstack.aws.api.cloudformation import StackStatus
    from localstack.services.cloudformation.stores import cloudformation_stores

    for _, _, store in cloudformation_stores.iter_stores():
        for stack in store.stacks.values():
            if terminal := _IN_PROGRESS_STACK_TERMINALS.get(stack.status):
                stack.set_stack_status(terminal, _STACK_RESTART_REASON)
        for stack in store.stacks_v2.values():
            if terminal := _IN_PROGRESS_STACK_TERMINALS.get(stack.status):
                stack.set_stack_status(StackStatus(terminal), _STACK_RESTART_REASON)


def _reset_restored_sqs_queues() -> None:
    from localstack.services.sqs.models import FifoQueue, StandardQueue, sqs_stores

    for _, _, store in sqs_stores.iter_stores():
        for queue in store.queues.values():
            # SqsProvider.on_before_stop shuts queues down to unblock receivers. The flag is
            # process-local and must not survive a restart, regardless of hook ordering.
            if isinstance(queue, StandardQueue):
                queue.visible.is_shutdown = False
            elif isinstance(queue, FifoQueue):
                queue.message_group_queue.is_shutdown = False


@hooks.on_infra_shutdown(priority=100, should_load=_native_snapshot_save_enabled)
def save_native_service_snapshots() -> None:
    from localstack.state.service_persistence import (
        native_service_stores,
        save_service_snapshots,
    )

    save_service_snapshots(config.dirs.data, native_service_stores())


@hooks.on_infra_start()
def deprecation_warnings() -> None:
    LOG.debug("Checking for the usage of deprecated community features and configs...")
    from localstack.deprecations import log_deprecation_warnings

    log_deprecation_warnings()


@hooks.on_infra_start(should_load=lambda: config.REMOVE_SSL_CERT)
def delete_cached_certificate():
    LOG.debug("Removing the cached local SSL certificate")
    target_file = get_cert_pem_file_path()
    rm_rf(target_file)


class OASPlugin(Plugin):
    """
    This plugin allows to register an arbitrary number of OpenAPI specs, e.g., the spec for the public endpoints
    of localstack.core.
    The OpenAPIValidator handler uses (as opt-in) all the collected specs to validate the requests and the responses
    to these public endpoints.

    An OAS plugin assumes the following directory layout.

    my_package
    ├── sub_package
    │   ├── __init__.py       <-- spec file
    │   ├── openapi.yaml
    │   └── plugins.py        <-- plugins
    ├── plugins.py            <-- plugins
    └── openapi.yaml          <-- spec file

    Each package can have its own OpenAPI yaml spec which is loaded by the correspondent plugin in plugins.py
    You can simply create a plugin like the following:

    class MyPackageOASPlugin(OASPlugin):
        name = "my_package"

    The only convention is that plugins.py and openapi.yaml have the same pathname.
    """

    namespace = "localstack.openapi.spec"

    def __init__(self) -> None:
        # By convention a plugins.py is at the same level (i.e., same pathname) of the openapi.yaml file.
        # importlib.resources would be a better approach but has issues with namespace packages in editable mode
        _module = sys.modules[self.__module__]
        self.spec_path = Path(
            os.path.join(os.path.dirname(os.path.abspath(_module.__file__)), "openapi.yaml")
        )
        assert self.spec_path.exists()
        self.spec = {}

    def load(self):
        with self.spec_path.open("r") as f:
            self.spec = yaml.safe_load(f)


class CoreOASPlugin(OASPlugin):
    name = "localstack"
