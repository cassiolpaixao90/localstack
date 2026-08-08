"""Static AWS capability catalog generation.

The generated catalog is deliberately conservative: source inspection can identify
generated stubs, provider overrides, and configured fallbacks, but it cannot prove
AWS parity. Promotions to ``native`` and ``parity-pass`` require runtime evidence.
"""

from localstack.capabilities.catalog import build_catalog, load_botocore_models

__all__ = ["build_catalog", "load_botocore_models"]
