"""Cross-platform local process lock, released by the OS even on process death.

All cooperating primary/standby instances MUST use the same state directory.
This is a single-host guard, not distributed fencing or network-filesystem locking.
"""
import os
from pathlib import Path


class AlreadyActive(Exception):
    pass


class PrimaryLock:
    def __init__(self, directory):
        self.path = Path(directory) / 'primary.lock'
        self.stream = None

    def __enter__(self):
        self.stream = self.path.open('a+b')
        try:
            if os.name == 'nt':
                import msvcrt
                self.stream.seek(0, 2)
                if self.stream.tell() == 0:
                    self.stream.write(b'\0')
                    self.stream.flush()
                self.stream.seek(0)
                msvcrt.locking(self.stream.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(self.stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            self.stream.close()
            self.stream = None
            raise AlreadyActive('Primary ownership is held or cannot be acquired') from exc
        return self

    def __exit__(self, *_):
        if self.stream is not None:
            # Closing releases the OS lock. Never delete the persistent lock file.
            self.stream.close()
            self.stream = None
