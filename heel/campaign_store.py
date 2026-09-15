"""Descriptor-anchored, owner-private campaign ledger and immutable reports."""
from __future__ import annotations

from contextlib import contextmanager
import os
from pathlib import Path
import re
import secrets
import stat

from .campaign_contract import canonical, strict_json
from .local_projects import LocalProjectStore, _enforce_mode
from .scope import heel_home


@contextmanager
def campaign_store():
    import fcntl
    store = LocalProjectStore(Path(heel_home()) / 'campaigns')
    directory = store._open_root(create=True)
    lock = None
    try:
        _enforce_mode(directory, 0o700, 'campaign directory')
        lock = os.open('.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600, dir_fd=directory)
        if not stat.S_ISREG(os.fstat(lock).st_mode) or os.fstat(lock).st_nlink != 1:
            raise ValueError('unsafe campaign lock')
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise ValueError('another campaign is active in this Heel home') from None
        yield CampaignStore(directory)
    finally:
        if lock is not None:
            os.close(lock)
        os.close(directory)


class CampaignStore:
    def __init__(self, directory):
        self.directory = directory

    def read(self, name):
        descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=self.directory)
        with os.fdopen(descriptor, 'rb') as source:
            status = os.fstat(source.fileno())
            if not stat.S_ISREG(status.st_mode) or status.st_nlink != 1 or status.st_size > 256*1024:
                raise ValueError('unsafe campaign record')
            return strict_json(source.read(256*1024+1))

    def write(self, name, value, *, replace=False):
        temporary = '.pending-' + secrets.token_hex(12)
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=self.directory)
        try:
            with os.fdopen(descriptor, 'w') as target:
                target.write(canonical(value)); target.flush(); os.fsync(target.fileno())
            if not replace:
                # link is an atomic, non-overwriting publication of the private inode.
                os.link(temporary, name, src_dir_fd=self.directory, dst_dir_fd=self.directory, follow_symlinks=False)
                os.unlink(temporary, dir_fd=self.directory)
            else:
                os.replace(temporary, name, src_dir_fd=self.directory, dst_dir_fd=self.directory)
            os.fsync(self.directory)
        finally:
            try:
                os.unlink(temporary, dir_fd=self.directory)
            except FileNotFoundError:
                pass

    def reserve(self, attempt, scope_id, maximum, allowance):
        if type(attempt) is not str or not re.fullmatch('[0-9a-f]{32}', attempt):
            raise ValueError('attempt must be 32 lowercase hexadecimal characters')
        try:
            ledger = self.read('ledger.json')
        except FileNotFoundError:
            ledger = {'attempts': [], 'reserved': {}}
        if attempt in ledger['attempts']:
            raise ValueError('campaign attempt already consumed')
        used = ledger['reserved'].get(scope_id, 0)
        if used + maximum > allowance:
            raise ValueError('signed scope campaign budget exhausted')
        if len(ledger['attempts']) >= 3000:
            raise ValueError('campaign ledger full; archive this home and authorize a new one')
        ledger['attempts'].append(attempt)
        ledger['reserved'][scope_id] = used + maximum
        self.write('ledger.json', ledger, replace=True)
