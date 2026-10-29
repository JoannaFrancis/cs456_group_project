"""Warm standby: wait without serving or sending beats; activate only on promotion."""
import argparse
import logging
import time
import uuid
from checkpoint import CheckpointError, finite_number, load_key, read_signed
from critical_service import add_arguments, configure_logging, run_service
from process_lock import AlreadyActive

LOG = logging.getLogger('standby')


def wait_for_promotion(args):
    key = load_key(args.state_dir)
    request = args.state_dir / 'promotion.request'
    LOG.info('[Standby Ready] Waiting for monitor promotion; no client listener or heartbeats')
    while True:
        if not request.exists():
            time.sleep(0.2)
            continue
        # Atomically claim the request: duplicate standby processes cannot consume it twice.
        claimed = args.state_dir / ('promotion.claimed.' + uuid.uuid4().hex)
        try:
            request.rename(claimed)
        except FileNotFoundError:
            continue
        try:
            payload = read_signed(claimed, key)
            if (not isinstance(payload, dict) or set(payload) != {
                    'action', 'requested_at', 'request_id'} or
                    payload['action'] != 'promote' or
                    not isinstance(payload['request_id'], str) or
                    not payload['request_id'] or
                    not finite_number(payload['requested_at']) or
                    not -5 <= time.time() - payload['requested_at'] <= 30):
                raise CheckpointError('Invalid or expired promotion request')
            LOG.info('[Promotion Received] request_id=%s', payload['request_id'])
            run_service(args, require_checkpoint=True, role='promoted-standby')
            return
        except AlreadyActive as exc:
            LOG.warning('[Promotion Refused] Existing primary ownership: %s', exc)
            # A fresh monitor request is needed after primary ownership is released.
        except (CheckpointError, OSError) as exc:
            LOG.error('[Promotion Refused] Recovery failed; checkpoint kept unchanged: %s', exc)
        finally:
            claimed.unlink(missing_ok=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    add_arguments(parser)
    args = parser.parse_args()
    if args.sim_leak:
        parser.error('Standby must not inherit the primary failure simulation')
    configure_logging(args.verbose)
    try:
        wait_for_promotion(args)
    except KeyboardInterrupt:
        LOG.info('Standby stopped')
    except (CheckpointError, OSError) as exc:
        LOG.error('Standby startup failed: %s', exc)
        raise SystemExit(1)
