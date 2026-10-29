"""CS456 Part 2: authentication, push heartbeats, and passive checkpoint recovery.
Python 3.10+
"""
import argparse
import json
import logging
import math
import os
import secrets
import socket
import threading
import time
import uuid
import random
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from checkpoint import CheckpointError, load_checkpoint, load_key, save_checkpoint
from process_lock import AlreadyActive, PrimaryLock
from settings import DEFAULT_STATE_DIR

LOG = logging.getLogger('auth-service')
# Intentionally dummy credentials. Never reuse real passwords in this prototype.
USERS = {'alice': 'alice-demo', 'bob': 'bob-demo'}
MAX_BODY_BYTES = 4096
MAX_TICKETS = 1000
LEAK_MAX = 8 * 1024 * 1024 # 8 MiB

class TicketStore:
    """Thread-safe tickets with live monotonic deadlines and portable saved deadlines."""
    def __init__(self, ttl=60.0):
        self.ttl = ttl
        self.tickets = {}
        self.lock = threading.RLock()

    def purge(self):
        with self.lock:
            now = time.monotonic()
            self.tickets = {t: value for t, value in self.tickets.items() if value[1] > now}

    def issue(self, username):
        with self.lock:
            self.purge()
            if len(self.tickets) >= MAX_TICKETS:
                return None
            ticket = secrets.token_urlsafe(32)
            self.tickets[ticket] = (username, time.monotonic() + self.ttl,
                                    time.time() + self.ttl)
            return ticket

    def validate(self, ticket):
        with self.lock:
            self.purge()
            entry = self.tickets.get(ticket)
            return entry[0] if entry else None

    def revoke(self, ticket):
        with self.lock:
            self.purge()
            return self.tickets.pop(ticket, None) is not None

    def snapshot(self):
        with self.lock:
            self.purge()
            return {token: {'username': entry[0], 'expires_at': entry[2]}
                    for token, entry in self.tickets.items()}

    def restore(self, saved_tickets):
        # Caller validates schema/signature before this method changes live state.
        wall_now, mono_now = time.time(), time.monotonic()
        with self.lock:
            self.tickets = {
                token: (entry['username'], mono_now + entry['expires_at'] - wall_now,
                        entry['expires_at'])
                for token, entry in saved_tickets.items()
                if entry['expires_at'] > wall_now
            }


def checkpoint_loop(stop_event, path, key, store, instance_id, interval):
    """Only the current owner runs this writer; no credentials/tickets enter logs."""
    while not stop_event.wait(interval):
        try:
            snapshot = store.snapshot()
            save_checkpoint(path, key, snapshot, instance_id)
            LOG.info('Checkpoint saved: %d active ticket(s)', len(snapshot))
        except (OSError, ValueError) as exc:
            LOG.error('Checkpoint write failed; recovery snapshot is aging: %s', exc)


def start_failure_simulation(stop_event):
    memory_leak_thread = threading.Thread(
        target=memory_leak_loop,
        args=(stop_event,)
    )
    memory_leak_thread.start()
    return memory_leak_thread

def memory_leak_loop(stop_event):
    bytearray_blocks = []  # Retain references so blocks are not reclaimed.
    total_leaked = 0 #prevents the simulated memory leak from going too far
    while not stop_event.is_set():
        delay = random.uniform(0.001, 1.4)
        if stop_event.wait(delay): 
            break # Exit loop if stop_event triggered

        chunk_size = random.randint(10240, 102400) # 10KiB to 100KiB
        block = bytearray(chunk_size)

        # Touch one byte of the block; this is not a physical-RAM measurement.
        block[random.randint(0, chunk_size - 1)] = 0xFF

        bytearray_blocks.append(block)
        total_leaked += chunk_size

        if total_leaked >= LEAK_MAX:
            LOG.critical("Simulated memory exhaustion: retained %d bytes; "
                         "terminating service process", total_leaked)
            os._exit(1)


def send_heartbeats(stop_event, monitor_host, monitor_port, interval, instance_id):
    """Push one JSON datagram immediately, then approximately every T seconds.

    This is the SERVICE SIDE, not the independent monitoring process. Missing
    monitor or UDP errors must not terminate authentication. No credentials or
    tickets are included. Sequence gaps are possible because UDP can lose data.
    """
    sequence = 0
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(0.5)
        while not stop_event.is_set():
            sequence += 1
            packet = {
                'type': 'HEARTBEAT', 'service': 'auth-ticket-service',
                'instance_id': instance_id, 'pid': os.getpid(),
                'sequence': sequence, 'timestamp': time.time(),
            }
            try:
                sock.sendto(json.dumps(packet).encode('utf-8'), (monitor_host, monitor_port))
                LOG.debug('Heartbeat %d sent', sequence)
            except OSError as exc:
                LOG.warning('Heartbeat send failed: %s', exc)
            if stop_event.wait(interval):
                break


class AuthHandler(BaseHTTPRequestHandler):
    # Keep requests sequential and bounded for this intentionally minimal service.
    def setup(self):
        super().setup()
        self.connection.settimeout(3.0)

    def log_message(self, format, *args):
        # Do not log request paths, bodies, passwords, or ticket values.
        pass

    def reply(self, status, payload):
        body = json.dumps(payload).encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def do_GET(self):
        if self.path != '/health':
            return self.reply(404, {'error': 'Unknown endpoint'})
        self.reply(200, {'status': 'ready', 'instance_id': self.server.instance_id,
                         'role': self.server.role})

    def do_POST(self):
        if self.path not in ('/login', '/validate', '/logout'):
            return self.reply(404, {'error': 'Unknown endpoint'})
        # The protocol requires a fixed-size JSON body; chunked encoding unsupported.
        if self.headers.get('Transfer-Encoding'):
            return self.reply(400, {'error': 'Transfer-Encoding is unsupported'})
        try:
            length = int(self.headers.get('Content-Length', '0'))
        except ValueError:
            return self.reply(400, {'error': 'Invalid Content-Length'})
        if length <= 0 or length > MAX_BODY_BYTES:
            return self.reply(400, {'error': 'Body must be 1 to 4096 bytes'})
        try:
            raw = self.rfile.read(length)
            if len(raw) != length:
                return self.reply(400, {'error': 'Incomplete body'})
            data = json.loads(raw)
        except (ValueError, UnicodeDecodeError, OSError):
            return self.reply(400, {'error': 'Expected a complete JSON object'})
        if not isinstance(data, dict):
            return self.reply(400, {'error': 'Expected a JSON object'})
        store = self.server.store
        if self.path == '/login':
            username, password = data.get('username'), data.get('password')
            if not isinstance(username, str) or not isinstance(password, str):
                return self.reply(400, {'error': 'username and password must be strings'})
            expected = USERS.get(username)
            if expected is None or password != expected:
                LOG.info('Login rejected')
                return self.reply(401, {'error': 'Invalid credentials'})
            ticket = store.issue(username)
            if ticket is None:
                return self.reply(503, {'error': 'Ticket capacity reached; try later'})
            LOG.info('Login accepted; ticket issued')
            return self.reply(200, {'ticket': ticket, 'expires_in_seconds': store.ttl})
        ticket = data.get('ticket')
        if not isinstance(ticket, str) or not ticket:
            return self.reply(400, {'error': 'ticket must be a nonempty string'})
        if self.path == '/validate':
            username = store.validate(ticket)
            if username is None:
                return self.reply(401, {'valid': False})
            return self.reply(200, {'valid': True, 'username': username})
        if not store.revoke(ticket):
            return self.reply(401, {'error': 'Invalid or expired ticket'})
        self.reply(200, {'revoked': True})


def positive_seconds(value):
    result = float(value)
    if not math.isfinite(result) or result <= 0:
        raise argparse.ArgumentTypeError('must be a finite positive number')
    return result


def port_number(value):
    result = int(value)
    if not 1 <= result <= 65535:
        raise argparse.ArgumentTypeError('must be between 1 and 65535')
    return result


class ServiceHTTPServer(HTTPServer):
    # Unix allows quick reuse after crash; Windows keeps exclusive binding.
    allow_reuse_address = os.name != 'nt'


def add_arguments(parser):
    parser.add_argument('--host', default='127.0.0.1')
    parser.add_argument('--port', type=port_number, default=8000)
    parser.add_argument('--monitor-host', default='127.0.0.1')
    parser.add_argument('--monitor-port', type=port_number, default=9999)
    parser.add_argument('--heartbeat-interval', type=positive_seconds, default=1.0)
    parser.add_argument('--ticket-ttl', type=positive_seconds, default=60.0)
    parser.add_argument('--checkpoint-interval', type=positive_seconds, default=1.0)
    parser.add_argument('--state-dir', type=Path, default=DEFAULT_STATE_DIR)
    parser.add_argument('--verbose', action='store_true')
    parser.add_argument('--sim-leak', action='store_true',
                        help='Enable the original randomized failure simulation')


def configure_logging(verbose):
    logging.basicConfig(level=logging.DEBUG if verbose else logging.INFO,
                        format='%(asctime)s %(levelname)s %(message)s')


def run_service(args, require_checkpoint=False, role='primary'):
    """Acquire ownership BEFORE loading/binding/writing. Monitor owns promotion."""
    key = load_key(args.state_dir)
    path = args.state_dir / 'checkpoint.json'
    with PrimaryLock(args.state_dir):
        store = TicketStore(args.ticket_ttl)
        if require_checkpoint or path.exists():
            payload = load_checkpoint(path, key, USERS, MAX_TICKETS)
            store.restore(payload['tickets'])
            LOG.info('Checkpoint loaded: %d unexpired ticket(s); saved_at=%.3f',
                     len(store.snapshot()), payload['saved_at'])
        instance_id = str(uuid.uuid4())
        stop_event = threading.Event()
        # Validate checkpoint first; a bad checkpoint never becomes an empty service.
        with ServiceHTTPServer((args.host, args.port), AuthHandler) as server:
            server.store = store
            server.instance_id = instance_id
            server.role = role
            server.timeout = 0.2
            # A fresh primary creates its first snapshot; existing state was loaded above.
            save_checkpoint(path, key, store.snapshot(), instance_id)
            heartbeat = threading.Thread(target=send_heartbeats, daemon=True,
                args=(stop_event, args.monitor_host, args.monitor_port,
                      args.heartbeat_interval, instance_id), name='heartbeat-sender')
            writer = threading.Thread(target=checkpoint_loop, daemon=True,
                args=(stop_event, path, key, store, instance_id,
                      args.checkpoint_interval), name='checkpoint-writer')
            fault_worker = None
            try:
                heartbeat.start()
                writer.start()
                if args.sim_leak:
                    fault_worker = start_failure_simulation(stop_event)
                LOG.info('[Service Restored] role=%s address=http://%s:%d instance=%s',
                         role, args.host, args.port, instance_id)
                while not stop_event.is_set():
                    server.handle_request()
            except KeyboardInterrupt:
                LOG.info('Stopping service')
            finally:
                stop_event.set()
                heartbeat.join()
                writer.join()
                if fault_worker is not None:
                    fault_worker.join()
                # Normal shutdown preserves recent changes; os._exit bypasses this.
                save_checkpoint(path, key, store.snapshot(), instance_id)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    add_arguments(parser)
    args = parser.parse_args()
    configure_logging(args.verbose)
    try:
        run_service(args)
    except (AlreadyActive, CheckpointError, OSError) as exc:
        LOG.error('Service startup/recovery refused: %s', exc)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
