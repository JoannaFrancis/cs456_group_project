"""Signed, atomic JSON ticket checkpoints; standard library, Python 3.10+."""
import hashlib
import hmac
import json
import math
import os
from pathlib import Path
import secrets
import tempfile
import time

MAX_CHECKPOINT_BYTES = 1024 * 1024


class CheckpointError(Exception):
    """Missing, corrupted, untrusted, or invalid checkpoint state."""


def initialize_state(directory):
    """Explicit one-time setup; never silently replace a lost signing key."""
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    path = directory / 'checkpoint.key'
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(secrets.token_bytes(32))
        stream.flush()
        os.fsync(stream.fileno())
    return path


def load_key(directory):
    try:
        key = (Path(directory) / 'checkpoint.key').read_bytes()
    except OSError as exc:
        raise CheckpointError('Signing key unavailable; run init_state.py first') from exc
    if len(key) != 32:
        raise CheckpointError('Signing key must contain exactly 32 bytes')
    return key


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      allow_nan=False).encode('utf-8')


def atomic_write(path, data):
    """Flush a private temp file, then atomically replace the destination."""
    path = Path(path)
    fd, temporary = tempfile.mkstemp(prefix='.' + path.name + '.', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def sign_and_write(path, payload, key):
    data = canonical(payload)
    digest = hmac.new(key, data, hashlib.sha256).hexdigest()
    atomic_write(path, canonical({'payload': payload, 'hmac_sha256': digest}))


def no_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('Duplicate JSON key')
        result[key] = value
    return result


def read_signed(path, key):
    try:
        with Path(path).open('rb') as stream:
            raw = stream.read(MAX_CHECKPOINT_BYTES + 1)
        if len(raw) > MAX_CHECKPOINT_BYTES:
            raise ValueError('File exceeds size limit')
        envelope = json.loads(raw, object_pairs_hook=no_duplicate_keys)
        if not isinstance(envelope, dict) or set(envelope) != {'payload', 'hmac_sha256'}:
            raise ValueError('Invalid signed envelope')
        signature = envelope['hmac_sha256']
        expected = hmac.new(key, canonical(envelope['payload']), hashlib.sha256).hexdigest()
        if not isinstance(signature, str) or not hmac.compare_digest(signature, expected):
            raise ValueError('Signature verification failed')
        return envelope['payload']
    except (OSError, ValueError, TypeError, RecursionError) as exc:
        raise CheckpointError('Cannot trust signed state: ' + str(exc)) from exc


def finite_number(value):
    return type(value) in (int, float) and math.isfinite(value)


def save_checkpoint(path, key, tickets, instance_id):
    payload = {'version': 1, 'service': 'auth-ticket-service',
               'saved_at': time.time(), 'instance_id': instance_id, 'tickets': tickets}
    sign_and_write(path, payload, key)


def load_checkpoint(path, key, allowed_users, max_tickets=1000):
    payload = read_signed(path, key)
    if not isinstance(payload, dict) or set(payload) != {
            'version', 'service', 'saved_at', 'instance_id', 'tickets'}:
        raise CheckpointError('Invalid checkpoint schema')
    if type(payload['version']) is not int or payload['version'] != 1:
        raise CheckpointError('Unsupported checkpoint version')
    if payload['service'] != 'auth-ticket-service':
        raise CheckpointError('Wrong service in checkpoint')
    if not finite_number(payload['saved_at']) or payload['saved_at'] > time.time() + 5:
        raise CheckpointError('Invalid checkpoint timestamp')
    if not isinstance(payload['instance_id'], str) or not payload['instance_id']:
        raise CheckpointError('Invalid service instance')
    tickets = payload['tickets']
    if not isinstance(tickets, dict) or len(tickets) > max_tickets:
        raise CheckpointError('Invalid ticket collection')
    for token, entry in tickets.items():
        if not isinstance(token, str) or not 1 <= len(token) <= 128:
            raise CheckpointError('Invalid ticket identifier')
        if not isinstance(entry, dict) or set(entry) != {'username', 'expires_at'}:
            raise CheckpointError('Invalid ticket entry')
        if not isinstance(entry['username'], str) or entry['username'] not in allowed_users:
            raise CheckpointError('Unknown user in checkpoint')
        if not finite_number(entry['expires_at']):
            raise CheckpointError('Invalid ticket expiration')
    return payload
