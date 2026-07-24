"""SAGE persistent memory integration for RAPTOR."""

from .config import SageConfig
from .client import SageClient
from .hooks import (
    # CodeQL build flags (upgrade to mechanical pending U1)
    recall_context_for_codeql_build,
    store_codeql_build_reliability,
    # Fuzzing strategy (mechanical AFL flag inference)
    recall_context_for_fuzzing_strategy,
    store_fuzzing_strategy_outcome,
    # SCA (mechanical short-circuit)
    recall_context_for_sca,
    store_sca_outcomes,
)

__all__ = [
    "SageConfig",
    "SageClient",
    "recall_context_for_codeql_build",
    "store_codeql_build_reliability",
    "recall_context_for_fuzzing_strategy",
    "store_fuzzing_strategy_outcome",
    "recall_context_for_sca",
    "store_sca_outcomes",
]
