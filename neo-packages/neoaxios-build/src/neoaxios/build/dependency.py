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

"""Dependency graph and topological sort."""

from pathlib import Path
from typing import Dict, List, Set, TYPE_CHECKING
import re
import tomllib

if TYPE_CHECKING:
    from neoaxios.build.models import BuildPackage


def parse_package_dependencies(pyproject_path: Path) -> Set[str]:
    """Parse internal neoaxios dependencies from pyproject.toml.

    Args:
        pyproject_path: Path to pyproject.toml file

    Returns:
        Set of package names (without neoaxios- prefix) that this package depends on
    """
    try:
        with open(pyproject_path, 'rb') as f:
            data = tomllib.load(f)

        dependencies = data.get('project', {}).get('dependencies', [])

        # Extract neoaxios- dependencies
        internal_deps = set()
        for dep_spec in dependencies:
            # Parse dependency spec: "neoaxios-config>=1.0.0" -> "config"
            match = re.match(r'neoaxios-([a-z0-9-]+)', dep_spec, re.IGNORECASE)
            if match:
                internal_deps.add(match.group(1))

        return internal_deps

    except Exception:
        # If parsing fails, return empty set (no dependencies)
        return set()


def build_dependency_graph(packages: List["BuildPackage"]) -> Dict[str, Set[str]]:
    """Build dependency graph from package list.

    Args:
        packages: List of BuildPackage objects

    Returns:
        Dictionary mapping package names to their dependencies
    """
    graph = {}

    # Create mapping of package names to BuildPackage objects
    package_map = {pkg.name: pkg for pkg in packages}

    # Also handle packages with neoaxios- prefix
    for pkg in packages:
        if pkg.pyproject_path:
            with open(pkg.pyproject_path, 'rb') as f:
                data = tomllib.load(f)
                full_name = data.get('project', {}).get('name', '')
                if full_name and full_name != pkg.name:
                    package_map[full_name] = pkg

    for pkg in packages:
        if pkg.pyproject_path:
            deps = parse_package_dependencies(pkg.pyproject_path)

            # Filter to only dependencies that are in our build set
            valid_deps = set()
            for dep in deps:
                # Try with and without neoaxios- prefix
                if dep in package_map:
                    valid_deps.add(dep)
                elif f"neoaxios-{dep}" in package_map:
                    valid_deps.add(f"neoaxios-{dep}")

            graph[pkg.name] = valid_deps
        else:
            graph[pkg.name] = set()

    return graph


def topological_sort(graph: Dict[str, Set[str]]) -> List[List[str]]:
    """Perform topological sort on dependency graph, returning build levels.

    Args:
        graph: Dictionary mapping package names to their dependencies

    Returns:
        List of levels, where each level is a list of package names that can
        be built in parallel (all dependencies from previous levels)
    """
    # Count incoming edges for each node
    in_degree = {node: 0 for node in graph}
    for node in graph:
        for dep in graph[node]:
            if dep in in_degree:
                in_degree[dep] += 1

    # Find all nodes with no incoming edges (no dependents)
    # These are leaf nodes that nothing depends on - build them last
    # We want to build dependencies FIRST, so we reverse the graph logic

    # Rebuild graph in reverse: dependents -> dependencies
    reverse_graph = {node: set() for node in graph}
    for node, deps in graph.items():
        for dep in deps:
            if dep in reverse_graph:
                reverse_graph[dep].add(node)

    # Now do topological sort on reverse graph
    # Nodes with no dependencies (in original graph) go first
    levels = []
    remaining = set(graph.keys())

    while remaining:
        # Find nodes with all dependencies satisfied
        ready = set()
        for node in remaining:
            if all(dep not in remaining for dep in graph[node]):
                ready.add(node)

        if not ready:
            # Circular dependency - break it by taking any remaining node
            ready = {next(iter(remaining))}

        levels.append(sorted(ready))
        remaining -= ready

    return levels
