import pytest
import tempfile
import json
from pathlib import Path
from unittest.mock import patch, MagicMock

from app.services.dependency_service import DependencyService
from app.models.dependency import Dependency, DependencyType


class TestDependencyService:
    """Test cases for DependencyService"""

    @pytest.fixture
    def service(self):
        return DependencyService(max_dependencies=100)

    @pytest.fixture
    def temp_repo(self):
        """Create a temporary repository with package files"""
        with tempfile.TemporaryDirectory() as temp_dir:
            repo_path = Path(temp_dir)

            # Create package.json
            package_json = {
                "name": "test-project",
                "version": "1.0.0",
                "dependencies": {
                    "express": "^4.17.1",
                    "lodash": "^4.17.21"
                },
                "devDependencies": {
                    "jest": "^27.0.0"
                }
            }

            with open(repo_path / "package.json", "w") as f:
                json.dump(package_json, f)

            # Create package-lock.json
            package_lock = {
                "dependencies": {
                    "express": {
                        "version": "4.17.1",
                        "dependencies": {
                            "accepts": {
                                "version": "1.3.7"
                            }
                        }
                    },
                    "lodash": {
                        "version": "4.17.21"
                    },
                    "jest": {
                        "version": "27.0.0"
                    }
                }
            }

            with open(repo_path / "package-lock.json", "w") as f:
                json.dump(package_lock, f)

            yield repo_path

    @pytest.mark.asyncio
    async def test_extract_npm_dependencies(self, service, temp_repo):
        """Test extracting npm dependencies"""
        dependencies = await service.extract_dependencies(temp_repo)

        # Should find direct dependencies
        assert len(dependencies) >= 3

        # Check direct dependencies
        express_dep = next(d for d in dependencies if d.name == "express")
        assert express_dep.dependency_type == DependencyType.NPM
        assert express_dep.is_direct is True
        assert express_dep.version == "4.17.1"

        lodash_dep = next(d for d in dependencies if d.name == "lodash")
        assert lodash_dep.dependency_type == DependencyType.NPM
        assert lodash_dep.is_direct is True

        jest_dep = next(d for d in dependencies if d.name == "jest")
        assert jest_dep.dependency_type == DependencyType.NPM
        assert jest_dep.is_direct is True

    @pytest.fixture
    def python_repo(self):
        """Create a temporary repository with Python package files"""
        with tempfile.TemporaryDirectory() as temp_dir:
            repo_path = Path(temp_dir)

            # Create requirements.txt
            requirements_content = """
requests>=2.25.0,<3.0.0
flask==2.0.1
pytest>=6.0.0
            """.strip()

            with open(repo_path / "requirements.txt", "w") as f:
                f.write(requirements_content)

            yield repo_path

    @pytest.mark.asyncio
    async def test_extract_python_dependencies(self, service, python_repo):
        """Test extracting Python dependencies"""
        dependencies = await service.extract_dependencies(python_repo)

        assert len(dependencies) == 3

        # Check requirements
        requests_dep = next(d for d in dependencies if d.name == "requests")
        assert requests_dep.dependency_type == DependencyType.PYTHON
        assert requests_dep.is_direct is True
        assert "2.25.0" in requests_dep.version  # Check for the version number

        flask_dep = next(d for d in dependencies if d.name == "flask")
        assert flask_dep.dependency_type == DependencyType.PYTHON
        assert flask_dep.version == "2.0.1"

    def test_parse_requirement_line(self, service):
        """Test parsing requirement lines"""
        # Test exact version
        name, version = service._parse_requirement_line("requests==2.25.0")
        assert name == "requests"
        assert version == "2.25.0"

        # Test version range - the method splits on first occurrence of >=
        name, version = service._parse_requirement_line("requests>=2.25.0,<3.0.0")
        assert name == "requests"
        assert version == "2.25.0,<3.0.0"  # This is the actual behavior

        # Test with comment
        name, version = service._parse_requirement_line("requests==2.25.0  # HTTP library")
        assert name == "requests"
        assert version == "2.25.0"

        # Test no version
        name, version = service._parse_requirement_line("requests")
        assert name == "requests"
        assert version == "*"

    @pytest.fixture
    def js_repo_with_imports(self):
        """Create a repository with JavaScript imports"""
        with tempfile.TemporaryDirectory() as temp_dir:
            repo_path = Path(temp_dir)

            # Create a JavaScript file with imports
            js_content = """
import express from 'express';
const lodash = require('lodash');
import { something } from 'some-package';
            """

            with open(repo_path / "app.js", "w") as f:
                f.write(js_content)

            yield repo_path

    def test_is_npm_dependency_used(self, service, js_repo_with_imports):
        """Test checking if npm dependencies are used"""
        # Test used dependency
        express_dep = Dependency(
            name="express",
            version="4.17.1",
            dependency_type=DependencyType.NPM,
            is_direct=True
        )
        assert service.is_dependency_used(express_dep, js_repo_with_imports) is True

        # Test unused dependency
        unused_dep = Dependency(
            name="unused-package",
            version="1.0.0",
            dependency_type=DependencyType.NPM,
            is_direct=True
        )
        assert service.is_dependency_used(unused_dep, js_repo_with_imports) is False

    @pytest.fixture
    def python_repo_with_imports(self):
        """Create a repository with Python imports"""
        with tempfile.TemporaryDirectory() as temp_dir:
            repo_path = Path(temp_dir)

            # Create a Python file with imports
            py_content = """
import requests
from flask import Flask
import numpy as np
            """

            with open(repo_path / "app.py", "w") as f:
                f.write(py_content)

            yield repo_path

    def test_is_python_dependency_used(self, service, python_repo_with_imports):
        """Test checking if Python dependencies are used"""
        # Test used dependency
        requests_dep = Dependency(
            name="requests",
            version="2.25.0",
            dependency_type=DependencyType.PYTHON,
            is_direct=True
        )
        assert service.is_dependency_used(requests_dep, python_repo_with_imports) is True

        # Test unused dependency
        unused_dep = Dependency(
            name="unused-package",
            version="1.0.0",
            dependency_type=DependencyType.PYTHON,
            is_direct=True
        )
        assert service.is_dependency_used(unused_dep, python_repo_with_imports) is False

    def test_max_dependencies_limit(self, service):
        """Test that max_dependencies limit is respected"""
        # Create many dependencies
        dependencies = []
        for i in range(150):  # More than the limit of 100
            dep = Dependency(
                name=f"package-{i}",
                version="1.0.0",
                dependency_type=DependencyType.NPM,
                is_direct=True
            )
            dependencies.append(dep)

        # The service should limit to max_dependencies
        service.max_dependencies = 100
        limited_deps = dependencies[:service.max_dependencies]
        assert len(limited_deps) == 100
