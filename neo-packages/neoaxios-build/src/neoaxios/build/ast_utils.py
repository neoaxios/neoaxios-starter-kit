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

"""Shared AST visitor utilities for build-time static analysis.

Provides reusable functions and visitors for extracting imports, class names,
and decorator names from Python AST trees. Used by
validate_telemetry_coverage.py, validate_flightrecorder_coverage.py, and
validate_import_boundaries.py.
"""

import ast
from pathlib import Path
from typing import List, Optional, Set


def get_decorator_name(node: ast.expr) -> str:
    """Resolve a decorator AST node to its full dotted string name.

    Handles all decorator forms:
      - @name            -> "name"
      - @name.attr       -> "name.attr"
      - @name()          -> "name"
      - @name.attr()     -> "name.attr"
      - @a.b.c           -> "a.b.c"
      - @a.b.c()         -> "a.b.c"

    Args:
        node: An AST expression node from a decorator_list.

    Returns:
        The resolved decorator name as a dotted string, or "" if unresolvable.
    """
    if isinstance(node, ast.Name):
        return node.id
    elif isinstance(node, ast.Attribute):
        prefix = get_decorator_name(node.value)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    elif isinstance(node, ast.Call):
        return get_decorator_name(node.func)
    return ""


def extract_imports(tree: ast.Module) -> Set[str]:
    """Extract all import module names from an AST tree.

    Returns both the root module name and the full dotted path for each
    import statement. For ``from X.Y import Z``, returns {"X", "X.Y", "Z"}.

    Args:
        tree: A parsed AST module.

    Returns:
        Set of module name strings (root names and full dotted paths).
    """
    imports: Set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imports.add(alias.name.split(".")[0])
                imports.add(alias.name)
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                imports.add(node.module.split(".")[0])
                imports.add(node.module)
            for alias in node.names:
                imports.add(alias.name)
    return imports


def extract_classes(tree: ast.Module) -> Set[str]:
    """Extract top-level class definition names from an AST tree.

    Only returns class names defined at the module body level (not nested
    classes inside functions or other classes).

    Args:
        tree: A parsed AST module.

    Returns:
        Set of class name strings.
    """
    classes: Set[str] = set()
    for node in tree.body:
        if isinstance(node, ast.ClassDef):
            classes.add(node.name)
    return classes


def parse_all_from_init(init_path: Path) -> Optional[List[str]]:
    """Parse ``__all__`` from an ``__init__.py`` file using AST.

    Returns the list of symbol names in declaration order, or ``None`` if
    the file does not define ``__all__`` or cannot be parsed.

    Args:
        init_path: Path to the ``__init__.py`` file.

    Returns:
        Ordered list of symbol name strings, or None.
    """
    if not init_path.is_file():
        return None

    try:
        source = init_path.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=str(init_path))
    except (SyntaxError, UnicodeDecodeError):
        return None

    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == "__all__":
                    return _extract_string_list(node.value)
        elif isinstance(node, ast.AugAssign):
            if isinstance(node.target, ast.Name) and node.target.id == "__all__":
                return _extract_string_list(node.value)
    return None


def _extract_string_list(node: ast.expr) -> Optional[List[str]]:
    """Extract a list of string literals from an AST node.

    Handles ``List``, ``Tuple``, and ``BinOp`` (concatenation) nodes
    where all elements are string constants.
    """
    if isinstance(node, (ast.List, ast.Tuple)):
        result = []
        for elt in node.elts:
            if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                result.append(elt.value)
        return result if result else None
    elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left = _extract_string_list(node.left)
        right = _extract_string_list(node.right)
        if left is not None and right is not None:
            return left + right
    return None


class ImportVisitor(ast.NodeVisitor):
    """Reusable AST visitor that extracts imports, class names, and decorator names.

    Combines import extraction, class extraction, and decorator extraction into
    a single-pass visitor. After calling ``visit(tree)``, the ``imports``,
    ``classes``, and ``decorators`` attributes contain the extracted names.

    Attributes:
        imports: Set of module name strings (root and dotted).
        classes: Set of top-level class name strings.
        decorators: Set of decorator name strings.
    """

    def __init__(self):
        self.imports: Set[str] = set()
        self.classes: Set[str] = set()
        self.decorators: Set[str] = set()

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            self.imports.add(alias.name.split(".")[0])
            self.imports.add(alias.name)
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if node.module:
            self.imports.add(node.module.split(".")[0])
            self.imports.add(node.module)
        for alias in node.names:
            self.imports.add(alias.name)
        self.generic_visit(node)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self.classes.add(node.name)
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._extract_decorators(node)
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._extract_decorators(node)
        self.generic_visit(node)

    def _extract_decorators(self, node: ast.AST) -> None:
        for dec in node.decorator_list:
            name = get_decorator_name(dec)
            if name:
                self.decorators.add(name)
