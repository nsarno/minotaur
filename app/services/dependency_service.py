import json
import re
from pathlib import Path
from typing import List, Dict, Any, Set
import toml
from packaging import version

from ..models.dependency import Dependency, DependencyType


class DependencyService:
    """Service for parsing and resolving dependencies from package files"""

    def __init__(self, max_dependencies: int = 1000):
        self.max_dependencies = max_dependencies

    async def extract_dependencies(self, repo_path: Path) -> List[Dependency]:
        """
        Extract all dependencies from a repository

        Args:
            repo_path: Path to the repository root

        Returns:
            List of all dependencies found
        """
        dependencies = []

        # Check for JavaScript/Node.js dependencies
        if (repo_path / "package.json").exists():
            npm_deps = await self._parse_npm_dependencies(repo_path)
            dependencies.extend(npm_deps)

        # Check for Python dependencies
        if (repo_path / "requirements.txt").exists():
            python_deps = await self._parse_requirements_txt(repo_path)
            dependencies.extend(python_deps)

        if (repo_path / "pyproject.toml").exists():
            poetry_deps = await self._parse_pyproject_toml(repo_path)
            dependencies.extend(poetry_deps)

        # Limit the number of dependencies
        if len(dependencies) > self.max_dependencies:
            dependencies = dependencies[:self.max_dependencies]

        return dependencies

    async def _parse_npm_dependencies(self, repo_path: Path) -> List[Dependency]:
        """Parse npm dependencies from package.json and package-lock.json"""
        dependencies = []

        # Parse package.json for direct dependencies
        package_json_path = repo_path / "package.json"
        with open(package_json_path, 'r') as f:
            package_data = json.load(f)

        # Extract direct dependencies
        direct_deps = {}
        direct_deps.update(package_data.get("dependencies", {}))
        direct_deps.update(package_data.get("devDependencies", {}))

        for name, version_spec in direct_deps.items():
            dependencies.append(Dependency(
                name=name,
                version=version_spec,
                dependency_type=DependencyType.NPM,
                is_direct=True,
                metadata={"source": "package.json"}
            ))

        # Parse package-lock.json for exact versions and transitive dependencies
        lock_file_path = repo_path / "package-lock.json"
        if lock_file_path.exists():
            with open(lock_file_path, 'r') as f:
                lock_data = json.load(f)

            # Extract all dependencies with exact versions
            all_deps = self._extract_npm_lock_dependencies(lock_data)

            # Update existing dependencies with exact versions
            for dep in dependencies:
                if dep.name in all_deps:
                    dep.version = all_deps[dep.name]["version"]
                    dep.metadata.update(all_deps[dep.name].get("metadata", {}))

            # Add transitive dependencies
            for name, dep_info in all_deps.items():
                if not any(d.name == name for d in dependencies):
                    dependencies.append(Dependency(
                        name=name,
                        version=dep_info["version"],
                        dependency_type=DependencyType.NPM,
                        is_direct=False,
                        parent=dep_info.get("parent"),
                        metadata=dep_info.get("metadata", {})
                    ))

        return dependencies

    def _extract_npm_lock_dependencies(self, lock_data: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
        """Extract all dependencies from package-lock.json"""
        dependencies = {}

        def process_dependencies(deps: Dict[str, Any], parent: str = None):
            for name, dep_info in deps.items():
                if isinstance(dep_info, dict) and "version" in dep_info:
                    dependencies[name] = {
                        "version": dep_info["version"],
                        "parent": parent,
                        "metadata": {
                            "integrity": dep_info.get("integrity"),
                            "resolved": dep_info.get("resolved")
                        }
                    }

                    # Process nested dependencies
                    if "dependencies" in dep_info:
                        process_dependencies(dep_info["dependencies"], name)

        if "dependencies" in lock_data:
            process_dependencies(lock_data["dependencies"])

        return dependencies

    async def _parse_requirements_txt(self, repo_path: Path) -> List[Dependency]:
        """Parse Python dependencies from requirements.txt"""
        dependencies = []
        requirements_path = repo_path / "requirements.txt"

        with open(requirements_path, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    # Parse requirement line (e.g., "requests>=2.25.0,<3.0.0")
                    name, version_spec = self._parse_requirement_line(line)
                    if name:
                        dependencies.append(Dependency(
                            name=name,
                            version=version_spec,
                            dependency_type=DependencyType.PYTHON,
                            is_direct=True,
                            metadata={"source": "requirements.txt"}
                        ))

        return dependencies

    async def _parse_pyproject_toml(self, repo_path: Path) -> List[Dependency]:
        """Parse Python dependencies from pyproject.toml"""
        dependencies = []
        pyproject_path = repo_path / "pyproject.toml"

        with open(pyproject_path, 'r') as f:
            pyproject_data = toml.load(f)

        # Check for poetry dependencies
        if "tool" in pyproject_data and "poetry" in pyproject_data["tool"]:
            poetry_data = pyproject_data["tool"]["poetry"]

            # Parse dependencies
            for dep_type in ["dependencies", "dev-dependencies"]:
                if dep_type in poetry_data:
                    for name, spec in poetry_data[dep_type].items():
                        if isinstance(spec, str):
                            version_spec = spec
                        elif isinstance(spec, dict):
                            version_spec = spec.get("version", "*")
                        else:
                            version_spec = "*"

                        dependencies.append(Dependency(
                            name=name,
                            version=version_spec,
                            dependency_type=DependencyType.PYTHON,
                            is_direct=True,
                            metadata={"source": "pyproject.toml", "type": dep_type}
                        ))

        return dependencies

    def _parse_requirement_line(self, line: str) -> tuple[str, str]:
        """Parse a single requirement line from requirements.txt"""
        # Remove comments
        line = line.split('#')[0].strip()

        # Handle different requirement formats
        if '==' in line:
            name, version = line.split('==', 1)
        elif '>=' in line:
            name, version = line.split('>=', 1)
        elif '<=' in line:
            name, version = line.split('<=', 1)
        elif '!=' in line:
            name, version = line.split('!=', 1)
        elif '~=' in line:
            name, version = line.split('~=', 1)
        elif '=' in line:
            name, version = line.split('=', 1)
        else:
            name, version = line, "*"

        return name.strip(), version.strip()

    def is_dependency_used(self, dependency: Dependency, repo_path: Path) -> bool:
        """
        Check if a dependency is actually used in the codebase

        Args:
            dependency: The dependency to check
            repo_path: Path to the repository root

        Returns:
            True if the dependency appears to be used
        """
        if dependency.dependency_type == DependencyType.NPM:
            return self._is_npm_dependency_used(dependency, repo_path)
        elif dependency.dependency_type == DependencyType.PYTHON:
            return self._is_python_dependency_used(dependency, repo_path)

        return True  # Default to True if we can't determine

    def _is_npm_dependency_used(self, dependency: Dependency, repo_path: Path) -> bool:
        """Check if an npm dependency is used in JavaScript/TypeScript files"""
        # Common patterns for npm imports
        import_patterns = [
            rf"import.*['\"]{re.escape(dependency.name)}['\"]",
            rf"require\(['\"]{re.escape(dependency.name)}['\"]\)",
            rf"from ['\"]{re.escape(dependency.name)}['\"]"
        ]

        return self._search_patterns_in_files(repo_path, import_patterns, ['.js', '.jsx', '.ts', '.tsx'])

    def _is_python_dependency_used(self, dependency: Dependency, repo_path: Path) -> bool:
        """Check if a Python dependency is used in Python files"""
        # Common patterns for Python imports
        import_patterns = [
            rf"import {re.escape(dependency.name)}",
            rf"from {re.escape(dependency.name)} import",
            rf"import {re.escape(dependency.name)} as",
        ]

        return self._search_patterns_in_files(repo_path, import_patterns, ['.py'])

    def _search_patterns_in_files(self, repo_path: Path, patterns: List[str], extensions: List[str]) -> bool:
        """Search for patterns in files with specific extensions"""
        for pattern in patterns:
            for file_path in repo_path.rglob('*'):
                if file_path.is_file() and file_path.suffix in extensions:
                    try:
                        with open(file_path, 'r', encoding='utf-8') as f:
                            content = f.read()
                            if re.search(pattern, content, re.IGNORECASE):
                                return True
                    except (UnicodeDecodeError, IOError):
                        continue

        return False
