"""
LevelDB backend implementation using plyvel.
"""
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator, Optional

import plyvel

from eth.db.backends.base import BaseAtomicDB


class LevelDB(BaseAtomicDB):
    """
    LevelDB backend using plyvel library.
    """

    def __init__(self, db_path: Path, max_open_files: int = 32) -> None:
        """
        Initialize a LevelDB instance.

        Args:
            db_path: Path to the database directory
            max_open_files: Maximum number of open files (default: 32)
        """
        self.db_path = Path(db_path)
        self.db_path.mkdir(parents=True, exist_ok=True)
        
        self._db = plyvel.DB(
            str(self.db_path),
            create_if_missing=True,
            max_open_files=max_open_files,
        )
        self._current_batch: Optional[plyvel.WriteBatch] = None

    def __getitem__(self, key: bytes) -> bytes:
        """Get a value from the database."""
        if not isinstance(key, bytes):
            raise TypeError(f"Key must be bytes, got {type(key)}")
        
        value = self._db.get(key)
        if value is None:
            raise KeyError(key)
        return value

    def __setitem__(self, key: bytes, value: bytes) -> None:
        """Set a value in the database."""
        if not isinstance(key, bytes):
            raise TypeError(f"Key must be bytes, got {type(key)}")
        if not isinstance(value, bytes):
            raise TypeError(f"Value must be bytes, got {type(value)}")
        
        if self._current_batch is not None:
            self._current_batch.put(key, value)
        else:
            self._db.put(key, value)
    def __delitem__(self, key: bytes) -> None:
        """Delete a value from the database."""
        if not isinstance(key, bytes):
            raise TypeError(f"Key must be bytes, got {type(key)}")
        
        if self._current_batch is not None:
            self._current_batch.delete(key)
        else:
            self._db.delete(key)

    def _exists(self, key: bytes) -> bool:
        """Check if a key exists in the database."""
        if not isinstance(key, bytes):
            raise TypeError(f"Key must be bytes, got {type(key)}")
        return self._db.get(key) is not None

    @contextmanager
    def atomic_batch(self) -> Iterator["LevelDB"]:
        """
        Context manager for atomic batch writes.
        
        All writes within the context are buffered and written atomically
        when the context exits successfully.
        """
        if self._current_batch is not None:
            raise ValueError("Already in an atomic batch context")
        
        self._current_batch = self._db.write_batch()
        try:
            yield self
            self._current_batch.write()
        except Exception:
            # Discard the batch on exception
            raise
        finally:
            self._current_batch = None

    def close(self) -> None:
        """Close the database connection."""
        if hasattr(self, '_db') and self._db is not None:
            self._db.close()
            self._db = None

    def __del__(self) -> None:
        """Cleanup database on deletion."""
        self.close()
