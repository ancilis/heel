"""Open-core local Heel runner primitives."""

from .identity import (
    RUNNER_CAPABILITIES, InMemorySecretBackend, LinuxSecretServiceBackend,
    MacOSKeychainSecretBackend, RunnerIdentity, RunnerPairingMaterial, SecureSigner,
    SystemSecureSigner, bind_runner_identity, create_runner_identity,
    create_runner_pairing_material, runner_phrase_words, validate_pairing_phrase,
)
from .control_client import (
    PendingRunnerResync, RecoveredRunnerChain, RunnerControlClient,
    RunnerRotationActivated,
)
from .catalog import AUTH_PROFILES, CATALOG, CATALOG_IDS, SEMANTIC_ROLES
from .compiler import CanaryCompiler, CompileResult
from .companion import CompanionServer, validate_disclosure_preview, validate_local_result_view
from .containment import (
    ContainmentError, ContainmentLog, LOCAL_EVENT_CODES, OPERATIONAL_EVENT_CODES,
    operational_containment_codes,
)
from .execution import (
    ExecutionBundle, ExecutionGate, ExecutionResult, LocalCanaryExecutor,
    ValidatedExecutionBundle, validate_execution_bundle,
)
from .http_transport import (
    BoundedResolver, CancellationToken, TargetHTTPSClient, TargetResponse, TransportFailure,
)
from .openapi_routes import RouteInventory, normalize_route_template
from .redaction import Redactor, safe_json_value
from .service import ClaimLease, Coordinator, LeaseExecutor, RunnerService
from .store import (
    RunnerContext, RunnerStore, RunnerStoreError, UnsupportedSecureStorageError,
    new_credential_handle_id,
)
from .vault import (
    EphemeralVault, KeychainVault, SecretServiceVault, UnavailableVault,
    VaultUnavailable, ephemeral_environment_name, read_inherited_secret,
    validate_credential_secret,
)

__all__ = [
    "RUNNER_CAPABILITIES", "RunnerIdentity", "RunnerPairingMaterial", "SecureSigner", "SystemSecureSigner",
    "InMemorySecretBackend", "MacOSKeychainSecretBackend", "LinuxSecretServiceBackend",
    "create_runner_identity", "create_runner_pairing_material", "bind_runner_identity",
    "runner_phrase_words", "validate_pairing_phrase", "RunnerControlClient",
    "PendingRunnerResync", "RecoveredRunnerChain",
    "RunnerRotationActivated",
    "AUTH_PROFILES", "CATALOG", "CATALOG_IDS", "SEMANTIC_ROLES",
    "CanaryCompiler", "CompileResult", "RouteInventory", "normalize_route_template",
    "CompanionServer", "validate_disclosure_preview", "validate_local_result_view",
    "ContainmentError", "ContainmentLog", "LOCAL_EVENT_CODES", "OPERATIONAL_EVENT_CODES",
    "operational_containment_codes", "ExecutionBundle", "ExecutionGate", "ExecutionResult",
    "LocalCanaryExecutor", "ValidatedExecutionBundle", "validate_execution_bundle",
    "BoundedResolver", "CancellationToken", "TargetHTTPSClient", "TargetResponse",
    "TransportFailure", "Redactor", "safe_json_value", "ClaimLease", "Coordinator",
    "LeaseExecutor", "RunnerService",
    "RunnerContext", "RunnerStore", "RunnerStoreError", "UnsupportedSecureStorageError",
    "new_credential_handle_id", "EphemeralVault", "KeychainVault",
    "SecretServiceVault", "UnavailableVault", "VaultUnavailable",
    "ephemeral_environment_name", "read_inherited_secret", "validate_credential_secret",
]
