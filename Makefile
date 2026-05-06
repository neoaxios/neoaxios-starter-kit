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

# NeoAxios Starter Kit top-level Makefile.
#
# `make build` invokes the neoaxios-build CLI (from neo-packages/neoaxios-build),
# which walks every pyproject.toml in the repo, builds wheels in parallel,
# then builds Docker images declared in build.yaml (docker_scan_paths).
# Both phases are content-hash cached — re-running make build with no source
# changes is a no-op that just verifies cache state.
#
# Common targets:
#   make build          - Build wheels + Docker images (parallel, cached)
#   make build-force    - Same as build but invalidates the cache
#   make build-wheels   - Wheels only (skip Docker images)
#   make clean          - Remove build/ dist/ __pycache__/ *.egg-info
#   make install-local  - pip install -e every package into the active venv
#   make help           - Show this help

ROOT := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))

# Cache root for wheel and Docker image artifacts produced by `make build`.
# Override by exporting NEOAXIOS_CACHE_ROOT before running make.
#
# - .wheel-cache/        contains branch-namespaced wheels (main/<wheel>.whl ...).
# - .docker-image-cache/ contains content-hashed image archives
#   (<hash>.tar.gz + <hash>.sha256 sidecar) consumed via `required_images`.
NEOAXIOS_CACHE_ROOT ?= $(HOME)/.cache/neoaxios
export NEOAXIOS_WHEEL_CACHE := $(NEOAXIOS_CACHE_ROOT)/.wheel-cache
export NEOAXIOS_IMAGE_CACHE := $(NEOAXIOS_CACHE_ROOT)/.docker-image-cache

# Python packages owned by this codebase (kept in sync with neo-packages/ tree).
# neoaxios-build is listed first so install-local bootstraps the build CLI.
PY_PACKAGES := \
    neo-packages/neoaxios-build \
    neo-packages/logging \
    neo-packages/foundation/config \
    neo-packages/foundation/secure_config \
    neo-packages/foundation/secure_cache \
    neo-packages/foundation/secret_store \
    neo-packages/foundation/stripe_kit \
    neo-packages/foundation/resilience-kit \
    neo-packages/foundation/test-foundation \
    neo-packages/foundation/sse-kit \
    neo-packages/foundation/fastapi_kit

PYTHON ?= python3
PIP    ?= pip

_COL_BLUE  := $(shell tput setaf 4 2>/dev/null)
_COL_GREEN := $(shell tput setaf 2 2>/dev/null)
_COL_DIM   := $(shell tput setaf 8 2>/dev/null)
_COL_RESET := $(shell tput sgr0   2>/dev/null)

.DEFAULT_GOAL := help
.PHONY: help build build-force build-wheels clean install-local check-neoaxios-build license-check

help:
	@printf "$(_COL_BLUE)NeoAxios Starter Kit$(_COL_RESET)\n"
	@printf "\n"
	@printf "  $(_COL_GREEN)make build$(_COL_RESET)          Build wheels + Docker images (parallel, cached)\n"
	@printf "  $(_COL_GREEN)make build-force$(_COL_RESET)    Same as build, disable cache\n"
	@printf "  $(_COL_GREEN)make build-wheels$(_COL_RESET)   Wheels only (skip Docker images)\n"
	@printf "  $(_COL_GREEN)make install-local$(_COL_RESET)  pip install -e every package into the active venv\n"
	@printf "  $(_COL_GREEN)make license-check$(_COL_RESET)  Verify per-package LICENSE files match top-level\n"
	@printf "  $(_COL_GREEN)make clean$(_COL_RESET)          Remove build artifacts\n"
	@printf "  $(_COL_GREEN)make help$(_COL_RESET)           Show this help\n"
	@printf "\n"
	@printf "  Build driver: $(_COL_DIM)python -m neoaxios.build --docker$(_COL_RESET) (reads build.yaml)\n"

# Fail early with a clear pointer if neoaxios-build isn't importable in the
# active environment. `make install-local` bootstraps it.
check-neoaxios-build:
	@$(PYTHON) -c 'import neoaxios.build' 2>/dev/null || { \
		printf "$(_COL_BLUE)neoaxios.build not installed in the active env.$(_COL_RESET)\n" >&2; \
		printf "  Run: make install-local           (installs every package editable)\n" >&2; \
		printf "  Or:  pip install -e $(ROOT)/neo-packages/neoaxios-build\n" >&2; \
		exit 1; \
	}

build: check-neoaxios-build license-check
	@cd $(ROOT) && $(PYTHON) -m neoaxios.build --docker

build-force: check-neoaxios-build license-check
	@cd $(ROOT) && $(PYTHON) -m neoaxios.build --force --docker

build-wheels: check-neoaxios-build license-check
	@cd $(ROOT) && $(PYTHON) -m neoaxios.build

# Verify every package ships an exact copy of the top-level Apache 2.0
# LICENSE so wheels distributed downstream carry the canonical license.
# Drift here is almost always accidental — fix by re-copying the top-level
# LICENSE.
license-check:
	@status=0; \
	for pkg in $(PY_PACKAGES); do \
		if [ ! -f "$(ROOT)/$$pkg/LICENSE" ]; then \
			printf "  MISSING: $$pkg/LICENSE\n" >&2; \
			status=1; \
		elif ! cmp -s "$(ROOT)/LICENSE" "$(ROOT)/$$pkg/LICENSE"; then \
			printf "  DRIFT:   $$pkg/LICENSE differs from top-level LICENSE\n" >&2; \
			status=1; \
		fi; \
	done; \
	if [ $$status -ne 0 ]; then \
		printf "$(_COL_BLUE)license-check failed.$(_COL_RESET) Re-sync with: cp LICENSE <pkg>/LICENSE\n" >&2; \
		exit 1; \
	fi; \
	printf "$(_COL_GREEN)==> license-check OK$(_COL_RESET) ($(words $(PY_PACKAGES)) packages)\n"

install-local:
	@if [ -z "$$VIRTUAL_ENV" ]; then \
		printf "refusing to install outside a venv; activate one first\n" >&2; \
		exit 1; \
	fi
	@for pkg in $(PY_PACKAGES); do \
		if grep -q '^test = ' "$(ROOT)/$$pkg/pyproject.toml" 2>/dev/null; then \
			printf "$(_COL_BLUE)==> pip install -e $$pkg\[test\]$(_COL_RESET)\n"; \
			$(PIP) install -e "$(ROOT)/$$pkg[test]" || exit 1; \
		else \
			printf "$(_COL_BLUE)==> pip install -e $$pkg$(_COL_RESET)\n"; \
			$(PIP) install -e "$(ROOT)/$$pkg" || exit 1; \
		fi; \
	done

clean:
	@printf "$(_COL_BLUE)==> removing build artifacts$(_COL_RESET)\n"
	@for pkg in $(PY_PACKAGES); do \
		rm -rf "$(ROOT)/$$pkg/build" \
		       "$(ROOT)/$$pkg/dist" \
		       "$(ROOT)/$$pkg"/*.egg-info \
		       2>/dev/null || true; \
	done
	@rm -rf "$(ROOT)/dist" "$(ROOT)/docker-images" 2>/dev/null || true
	@find $(ROOT)/neo-packages -type d -name '__pycache__' -exec rm -rf {} + 2>/dev/null || true
	@find $(ROOT)/neo-packages -type d -name '.pytest_cache' -exec rm -rf {} + 2>/dev/null || true
