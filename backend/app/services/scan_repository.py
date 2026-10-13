from collections import OrderedDict
from functools import lru_cache
import threading
from typing import Optional

from backend.app.schemas.scans import ScanResultResponse


class ScanRepository:
    """Thread-safe, bounded in-memory repository for vulnerability scan results.

    IMPORTANT ARCHITECTURAL NOTE:
    Scan results stored here are kept in transient memory and will NOT persist across server restarts.
    This serves as a bounded caching repository until database persistence (PostgreSQL/SQLite)
    is integrated in a subsequent milestone.
    """

    def __init__(self, max_items: int = 100) -> None:
        self._max_items = max_items
        self._lock = threading.Lock()
        self._storage: OrderedDict[str, ScanResultResponse] = OrderedDict()

    def save(self, scan_result: ScanResultResponse) -> None:
        """Store or update a scan result, evicting oldest entries when bounded capacity is reached."""
        with self._lock:
            # If item already exists, remove it first so it moves to most recent
            if scan_result.scan_id in self._storage:
                del self._storage[scan_result.scan_id]
            elif len(self._storage) >= self._max_items:
                # Evict oldest entry (FIFO)
                self._storage.popitem(last=False)
            self._storage[scan_result.scan_id] = scan_result

    def get(self, scan_id: str) -> Optional[ScanResultResponse]:
        """Retrieve a scan result by its UUID, or None if not found."""
        with self._lock:
            return self._storage.get(scan_id)

    def list_recent(self, limit: int = 50) -> list[ScanResultResponse]:
        """List recently stored scan results, ordered latest to oldest."""
        with self._lock:
            items = list(self._storage.values())
            items.reverse()
            return items[:limit]

    def count(self) -> int:
        """Return the current number of stored scan records."""
        with self._lock:
            return len(self._storage)

    def clear(self) -> None:
        """Clear all stored scans (primarily used for test isolation)."""
        with self._lock:
            self._storage.clear()


@lru_cache
def get_scan_repository() -> ScanRepository:
    """Provide a singleton instance of the in-memory scan repository."""
    return ScanRepository(max_items=100)
