from abc import ABC, abstractmethod

from ai_spm.engine.models import CloudResource


class BaseCollector(ABC):
    @abstractmethod
    def collect(self) -> list[CloudResource]:
        """Collect and normalize resources."""
        pass
