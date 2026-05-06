# Copyright 2026 NeoAxios LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""secret_store -- Vault-backed secret store for distributed Python services.

Public surface:
    - :class:`SecretStoreProtocol` -- contract for rotatable-secret retrieval
    - :class:`VaultSecretStore` -- concrete HashiCorp Vault implementation
    - :class:`VaultConfig` -- frozen dataclass carrying Vault connection params
    - :class:`VaultAuthError` / :class:`VaultUnavailableError` /
      :class:`SecretNotFoundError` -- structured error hierarchy

See :mod:`secret_store.core` for full documentation.
"""

from neoaxios_secret_store.core import (
    SecretNotFoundError,
    SecretStoreProtocol,
    VaultAuthError,
    VaultConfig,
    VaultSecretStore,
    VaultUnavailableError,
)

__version__ = "1.0.0"

__all__ = [
    "SecretStoreProtocol",
    "VaultSecretStore",
    "VaultConfig",
    "VaultAuthError",
    "VaultUnavailableError",
    "SecretNotFoundError",
]
