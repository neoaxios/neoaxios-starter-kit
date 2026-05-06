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

"""Permission resolvers for authorization sources.

Provides local database resolver and composite resolver for aggregating
multiple sources. Provider-specific resolvers (Azure, AWS, Google) can
be added as needed.

Usage:
    from neoaxios_fastapi_kit.auth.authz.resolvers import LocalResolver, CompositeResolver
"""

from neoaxios_fastapi_kit.auth.authz.resolvers.composite import (
    CompositeResolver,
    PrivilegeResolver,
    provider_based_selector,
    all_resolvers_selector,
)
from neoaxios_fastapi_kit.auth.authz.resolvers.local import LocalResolver

__all__ = [
    "CompositeResolver",
    "PrivilegeResolver",
    "provider_based_selector",
    "all_resolvers_selector",
    "LocalResolver",
]
