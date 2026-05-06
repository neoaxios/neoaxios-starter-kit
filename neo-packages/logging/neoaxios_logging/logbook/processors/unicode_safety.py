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

"""
Unicode safety processors for Logbook.

This module provides processors that ensure safe handling of unicode data,
preventing crashes from international characters or binary data.
"""

from structlog.processors import UnicodeDecoder, UnicodeEncoder


def create_unicode_processors(
    encoding: str = "utf-8",
    errors: str = "replace"
) -> tuple:
    """
    Create configured unicode safety processors.

    Returns two processors that work together to ensure safe unicode handling:
    1. UnicodeDecoder: Decodes byte strings to unicode (early in pipeline)
    2. UnicodeEncoder: Encodes unicode to UTF-8 (late in pipeline)

    Args:
        encoding: Character encoding to use (default: utf-8)
        errors: How to handle encoding errors:
                - 'replace': Replace invalid chars with ? (safest, default)
                - 'ignore': Skip invalid chars
                - 'strict': Raise exception on invalid chars

    Returns:
        Tuple of (unicode_decoder, unicode_encoder)

    Example:
        >>> decoder, encoder = create_unicode_processors()
        >>> # Add decoder early in pipeline (after merge_contextvars)
        >>> # Add encoder late in pipeline (before renderer)

    Notes:
        - UnicodeDecoder should be positioned early in the processor pipeline
        - UnicodeEncoder should be positioned late (before final renderer)
        - Default 'replace' mode ensures no crashes from invalid characters
    """
    # Create UnicodeDecoder
    # Decodes byte strings to unicode strings
    # Should be early in pipeline to ensure all processors work with unicode
    unicode_decoder = UnicodeDecoder(encoding=encoding, errors=errors)

    # Create UnicodeEncoder
    # Encodes unicode strings to bytes for output
    # Should be late in pipeline, before final renderer
    unicode_encoder = UnicodeEncoder(encoding=encoding, errors=errors)

    return (unicode_decoder, unicode_encoder)


# Default processor instances with safe settings
default_unicode_decoder, default_unicode_encoder = create_unicode_processors(
    encoding="utf-8",
    errors="replace"  # Safe default: replace invalid chars with ?
)
