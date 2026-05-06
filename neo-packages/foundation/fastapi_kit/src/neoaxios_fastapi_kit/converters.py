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

"""OpenAPI to function calling format converters."""

import re
from typing import Dict, Any, List, Optional

from neoaxios_logging import get_telemetry, auto_trace

logger = get_telemetry(__name__)


@auto_trace(logger)
def convert_openapi_to_function_calling(
    openapi_schema: Dict[str, Any],
    include_paths: Optional[List[str]] = None,
    exclude_paths: Optional[List[str]] = None,
) -> Dict[str, List[Dict[str, Any]]]:
    """
    Convert OpenAPI 3.x schema to OpenAI function calling format.

    Args:
        openapi_schema: Full OpenAPI 3.x schema from FastAPI
        include_paths: List of path patterns to include (regex)
        exclude_paths: List of paths to exclude (exact match or regex)

    Returns:
        {
            "tools": [
                {
                    "type": "function",
                    "function": {
                        "name": "operation_id",
                        "description": "Operation description",
                        "parameters": {...json schema...}
                    }
                }
            ]
        }

    Example:
        openapi = app.openapi()
        tools = convert_openapi_to_function_calling(openapi)
    """
    tools = []
    paths = openapi_schema.get("paths", {})

    for path, path_item in paths.items():
        # Check exclusions
        if exclude_paths and _should_exclude(path, exclude_paths):
            continue

        # Check inclusions
        if include_paths and not _should_include(path, include_paths):
            continue

        # Process each HTTP method
        for method, operation in path_item.items():
            if method.lower() not in ["get", "post", "put", "patch", "delete"]:
                continue

            if not isinstance(operation, dict):
                continue

            function_def = _convert_operation_to_function(
                operation, path, method
            )

            if function_def:
                tools.append({
                    "type": "function",
                    "function": function_def
                })

    return {"tools": tools}


# Private helpers - called per-path/per-operation in loops.


@auto_trace(logger)  # Called per path in conversion loop
def _should_exclude(path: str, exclude_paths: List[str]) -> bool:
    """Check if path should be excluded."""
    for pattern in exclude_paths:
        if path == pattern or re.match(pattern, path):
            return True
    return False


@auto_trace(logger)  # Called per path in conversion loop
def _should_include(path: str, include_paths: List[str]) -> bool:
    """Check if path should be included."""
    for pattern in include_paths:
        if path == pattern or re.match(pattern, path):
            return True
    return False


@auto_trace(logger)  # Called per operation in conversion loop
def _convert_operation_to_function(
    operation: Dict[str, Any],
    path: str,
    method: str,
) -> Optional[Dict[str, Any]]:
    """
    Convert single OpenAPI operation to function definition.

    Args:
        operation: OpenAPI operation object
        path: API path (e.g., /v1/analyze)
        method: HTTP method (e.g., POST)

    Returns:
        Function definition dict or None if invalid
    """
    # Get function name (prefer operationId, fallback to generated name)
    function_name = operation.get("operationId")
    if not function_name:
        # Generate name from path and method
        # /v1/analysis -> v1_analysis
        # POST /v1/analysis -> create_v1_analysis
        clean_path = path.strip("/").replace("/", "_").replace("-", "_")
        method_prefix = {
            "get": "get",
            "post": "create",
            "put": "update",
            "patch": "patch",
            "delete": "delete",
        }.get(method.lower(), method.lower())
        function_name = f"{method_prefix}_{clean_path}"

    # Get description (prefer summary, fallback to description)
    description = operation.get("summary") or operation.get("description") or f"{method.upper()} {path}"

    # Extract parameters schema
    parameters = _extract_parameters_schema(operation, path)

    return {
        "name": function_name,
        "description": description,
        "parameters": parameters,
    }


@auto_trace(logger)  # Called per operation in conversion loop
def _extract_parameters_schema(
    operation: Dict[str, Any],
    path: str,
) -> Dict[str, Any]:
    """
    Extract JSON schema for function parameters from OpenAPI operation.

    Combines:
    - Path parameters (from path template)
    - Query parameters
    - Request body (for POST/PUT/PATCH)

    Args:
        operation: OpenAPI operation object
        path: API path (may contain {param} templates)

    Returns:
        JSON schema for function parameters
    """
    properties = {}
    required = []

    # Extract path parameters
    if "{" in path:
        path_params = re.findall(r"\{([^}]+)\}", path)
        for param_name in path_params:
            properties[param_name] = {"type": "string"}
            required.append(param_name)

    # Extract query/path/header parameters from OpenAPI
    parameters = operation.get("parameters", [])
    for param in parameters:
        if not isinstance(param, dict):
            continue

        param_name = param.get("name")
        param_in = param.get("in")  # query, path, header, cookie
        param_schema = param.get("schema", {})
        param_required = param.get("required", False)

        if param_in in ["query", "path"]:
            properties[param_name] = param_schema
            if param_required:
                required.append(param_name)

    # Extract request body for POST/PUT/PATCH
    request_body = operation.get("requestBody", {})
    if request_body:
        content = request_body.get("content", {})
        json_content = content.get("application/json", {})
        body_schema = json_content.get("schema", {})

        if body_schema:
            # If body has properties, merge them
            if "properties" in body_schema:
                properties.update(body_schema["properties"])
                if "required" in body_schema:
                    required.extend(body_schema["required"])
            else:
                # If body is a reference or simple type, use as-is
                properties["body"] = body_schema
                if request_body.get("required", False):
                    required.append("body")

    # Build final schema
    schema = {
        "type": "object",
        "properties": properties,
    }

    if required:
        schema["required"] = list(set(required))  # Deduplicate

    return schema
