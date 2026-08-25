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
from .openapi_routes import RouteInventory, normalize_route_template
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
    "RunnerContext", "RunnerStore", "RunnerStoreError", "UnsupportedSecureStorageError",
    "new_credential_handle_id", "EphemeralVault", "KeychainVault",
    "SecretServiceVault", "UnavailableVault", "VaultUnavailable",
    "ephemeral_environment_name", "read_inherited_secret", "validate_credential_secret",
]
