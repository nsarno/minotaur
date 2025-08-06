from enum import Enum
from typing import Optional, Dict, Any
from pydantic import BaseModel, Field


class DependencyType(str, Enum):
    """Supported dependency types"""
    NPM = "npm"
    PYTHON = "python"


class Dependency(BaseModel):
    """Represents a package dependency"""
    name: str = Field(..., description="Package name")
    version: str = Field(..., description="Package version")
    dependency_type: DependencyType = Field(..., description="Type of dependency")
    is_direct: bool = Field(..., description="Whether this is a direct dependency")
    parent: Optional[str] = Field(None, description="Parent package if transitive")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Additional metadata")

    class Config:
        use_enum_values = True

    def __str__(self) -> str:
        return f"{self.name}@{self.version} ({self.dependency_type})"

    @property
    def package_key(self) -> str:
        """Unique key for package identification"""
        return f"{self.dependency_type}:{self.name}"
