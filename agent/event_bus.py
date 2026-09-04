"""
Event Bus module for LifeShield Agent.
Provides an asyncio-based queue to decouple event receiving from event storage.
Lazy, loop-aware queue initialization guarantees binding to the active running event loop.
"""
import sys
import asyncio
from pathlib import Path
from typing import Optional

sys.path.insert(0, str(Path(__file__).parent.parent))

from storage.schema import LifeShieldEvent


class EventBus:
    """
    Async queue wrapper for internal event routing.
    Uses loop-aware lazy initialization to re-bind queue whenever event loop changes.
    """

    def __init__(self, maxsize: int = 1000):
        self.maxsize = maxsize
        self._queue: Optional[asyncio.Queue[LifeShieldEvent]] = None
        self._loop: Optional[asyncio.AbstractEventLoop] = None

    def _get_queue(self) -> asyncio.Queue[LifeShieldEvent]:
        current_loop = asyncio.get_running_loop()
        if self._queue is None or self._loop != current_loop:
            self._queue = asyncio.Queue(maxsize=self.maxsize)
            self._loop = current_loop
        return self._queue

    async def put(self, event: LifeShieldEvent) -> None:
        """Pushes an event onto the queue."""
        await self._get_queue().put(event)

    async def get(self) -> LifeShieldEvent:
        """Pops an event from the queue."""
        return await self._get_queue().get()

    def task_done(self) -> None:
        """Marks a popped task as done."""
        if self._queue is not None:
            self._queue.task_done()

    @property
    def qsize(self) -> int:
        if self._queue is not None and self._loop == asyncio.get_running_loop():
            return self._queue.qsize()
        return 0

    @property
    def empty(self) -> bool:
        if self._queue is not None and self._loop == asyncio.get_running_loop():
            return self._queue.empty()
        return True


# Global singleton instance for the agent process
event_bus = EventBus()
