"""Monitor integration command: request promotion; standby reports actual readiness."""
import argparse
import secrets
import time
from pathlib import Path
from checkpoint import CheckpointError, load_key, sign_and_write
from settings import DEFAULT_STATE_DIR


def request_promotion(directory):
    directory = Path(directory)
    key = load_key(directory)
    payload = {'action': 'promote', 'requested_at': time.time(),
               'request_id': secrets.token_hex(16)}
    sign_and_write(directory / 'promotion.request', payload, key)
    return payload['request_id']


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--state-dir', default=DEFAULT_STATE_DIR)
    args = parser.parse_args()
    try:
        request_id = request_promotion(args.state_dir)
        print('[Failover Triggered] Promotion requested; id=' + request_id, flush=True)
        print('This confirms the request only. Wait for [Service Restored] and /health readiness.')
    except (CheckpointError, OSError) as exc:
        parser.exit(1, 'Promotion request failed: ' + str(exc) + '\n')
