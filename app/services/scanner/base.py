from abc import ABC, abstractmethod

import httpx

from app.schemas.scan import Issue


class BaseScanner(ABC):
    @abstractmethod
    async def scan(self, url: str, response: httpx.Response) -> list[Issue]:
        pass
