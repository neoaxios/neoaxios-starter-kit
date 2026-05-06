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

"""stripe_kit -- Structured error taxonomy for the Stripe Python SDK.

Public surface:
    - :class:`StripeAdapterError` and subclasses -- structured error
      hierarchy that adapters raise on Stripe SDK failures
    - :func:`translate_stripe_error` -- maps raw ``stripe.error.*``
      exceptions to :class:`StripeAdapterError` subclasses

See :mod:`stripe_kit.errors` for full documentation.
"""

from neoaxios_stripe_kit.errors import (
    StripeAdapterError,
    StripeAPIError,
    StripeAuthError,
    StripeInvalidRequestError,
    StripeSignatureVerificationError,
    translate_stripe_error,
)

__version__ = "0.0.1"

__all__ = [
    "StripeAdapterError",
    "StripeAPIError",
    "StripeAuthError",
    "StripeInvalidRequestError",
    "StripeSignatureVerificationError",
    "translate_stripe_error",
]
