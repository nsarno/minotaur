import os
import tempfile
import shutil
import asyncio
from pathlib import Path
from typing import Optional
import git
from urllib.parse import urlparse

from ..models.dependency import Dependency, DependencyType


class RepositoryService:
    """Service for cloning and managing GitHub repositories"""

    def __init__(self, clone_timeout: int = 300):
        self.clone_timeout = clone_timeout
        self.temp_dir = None

    async def clone_repository(self, repo_url: str) -> Path:
        """
        Clone a GitHub repository to a temporary directory

        Args:
            repo_url: GitHub repository URL

        Returns:
            Path to the cloned repository

        Raises:
            ValueError: If URL is not a valid GitHub repository
            git.GitCommandError: If cloning fails
        """
        if not self._is_valid_github_url(repo_url):
            raise ValueError(f"Invalid GitHub URL: {repo_url}")

        # Create temporary directory
        self.temp_dir = tempfile.mkdtemp(prefix="minotaur_")
        repo_path = Path(self.temp_dir)

        try:
            # Clone the repository with timeout
            await asyncio.wait_for(
                asyncio.to_thread(
                    git.Repo.clone_from,
                    repo_url,
                    repo_path,
                    depth=1  # Shallow clone for speed
                ),
                timeout=self.clone_timeout
            )

            return repo_path

        except asyncio.TimeoutError:
            # Clean up on timeout
            self.cleanup()
            raise TimeoutError(f"Repository cloning timed out after {self.clone_timeout} seconds")
        except git.GitCommandError as e:
            # Clean up on failure
            self.cleanup()
            raise e

    def _is_valid_github_url(self, url: str) -> bool:
        """Check if URL is a valid GitHub repository URL"""
        try:
            parsed = urlparse(url)
            return (
                parsed.scheme in ('http', 'https') and
                parsed.netloc in ('github.com', 'www.github.com') and
                len(parsed.path.strip('/').split('/')) >= 2
            )
        except Exception:
            return False

    def get_repo_name(self, repo_url: str) -> str:
        """Extract repository name from GitHub URL"""
        parsed = urlparse(repo_url)
        path_parts = parsed.path.strip('/').split('/')
        if len(path_parts) >= 2:
            return f"{path_parts[0]}/{path_parts[1]}"
        raise ValueError(f"Invalid GitHub URL: {repo_url}")

    def cleanup(self):
        """Clean up temporary repository directory"""
        if self.temp_dir and os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)
            self.temp_dir = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.cleanup()
