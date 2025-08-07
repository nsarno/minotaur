from enum import Enum
from typing import Optional, Dict, Any
from pydantic import BaseModel, ConfigDict


class DependencyType(str, Enum):
    """Dependency type enumeration"""
    NPM = "npm"
    PYTHON = "python"


class Dependency(BaseModel):
    """Represents a software dependency"""
    name: str
    version: str
    dependency_type: DependencyType
    is_direct: bool = True
    parent: Optional[str] = None
    metadata: Dict[str, Any] = {}

    model_config = ConfigDict(from_attributes=True)

    def __str__(self) -> str:
        return f"{self.name}@{self.version} ({self.dependency_type})"

    @property
    def package_key(self) -> str:
        """Unique key for package identification"""
        return f"{self.dependency_type}:{self.name}"
