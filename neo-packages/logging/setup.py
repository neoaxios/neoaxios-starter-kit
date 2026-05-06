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

"""Setup script for NeoAxios Telemetry package."""

from setuptools import setup, find_packages
from pathlib import Path

# Read README for long description
readme_file = Path(__file__).parent / "README.md"
long_description = readme_file.read_text() if readme_file.exists() else ""

setup(
    name="neoaxios-logging",
    version="1.0.0",
    author="NeoAxios",
    author_email="engineering@neoaxios.com",
    description="Production-level telemetry and logging for distributed systems",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/neoaxios/neoaxios-starter-kit",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "Topic :: System :: Logging",
        "Topic :: System :: Monitoring",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
    ],
    python_requires=">=3.8",
    install_requires=[
        "psutil>=5.8.0",  # For process telemetry
        "structlog>=23.0.0",  # For structured logging
        "pyyaml>=5.1",  # For configuration files
    ],
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "pytest-asyncio>=0.21.0",
            "black>=22.0.0",
            "mypy>=0.950",
        ],
    },
    entry_points={
        "console_scripts": [
            # FlightRecorder management tools (full names)
            "neoaxios-fr-cleanup=neoaxios_logging.scripts.cleanup:main",
            "neoaxios-fr-query=neoaxios_logging.scripts.query:main",

            # Short aliases for convenience
            "neo-fr-cleanup=neoaxios_logging.scripts.cleanup:main",
            "neo-fr-query=neoaxios_logging.scripts.query:main",
        ],
    },
)
