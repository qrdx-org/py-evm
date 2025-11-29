"""
Warning utilities for eth module imports.
"""
import contextlib
import warnings
from typing import Iterator


@contextlib.contextmanager
def catch_and_ignore_import_warning() -> Iterator[None]:
    """
    Context manager to catch and ignore import warnings.
    
    This is used during module initialization to suppress warnings
    about deprecated or experimental features being imported.
    """
    with warnings.catch_warnings():
        warnings.filterwarnings("ignore", category=DeprecationWarning)
        warnings.filterwarnings("ignore", category=PendingDeprecationWarning)
        warnings.filterwarnings("ignore", category=ImportWarning)
        yield
