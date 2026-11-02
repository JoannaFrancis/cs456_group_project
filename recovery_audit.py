
"""
Authorized Part 2 recovery audit utility.

Run from the project folder:

    python recovery_audit.py false-failover --state-dir "$env:LOCALAPPDATA\CS456-State"

After the primary crashes, before recovery:

    python recovery_audit.py tamper-checkpoint --state-dir "$env:LOCALAPPDATA\CS456-State"

Restore the real checkpoint afterward:

    python recovery_audit.py restore-checkpoint --state-dir "$env:LOCALAPPDATA\CS456-State"
"""

import argparse
import json
import time
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import urlopen

from checkpoint import CheckpointError
from promote_standby import request_promotion
from settings import DEFAULT_STATE_DIR


BACKUP_NAME = "checkpoint.audit-backup.json"


def get_health(health_url):
    """Return the service health information, or None if it is unavailable."""
    try:
        with urlopen(health_url, timeout=1.0) as response:
            if response.status != 200:
                return None

            body = json.load(response)

            if isinstance(body, dict):
                return body

    except (HTTPError, URLError, OSError, ValueError, TimeoutError):
        return None

    return None


def false_failover_test(state_dir, health_url, wait_seconds):
    """
    Simulates a faulty monitor attempting to promote standby even though
    the primary is alive.

    The standby should refuse because the living primary owns primary.lock.
    """
    before = get_health(health_url)

    if before is None or before.get("role") != "primary":
        print("[FAIL] A healthy primary must be running before this test.")
        return

    primary_id = before.get("instance_id")
    print("[Audit] Healthy primary confirmed.")
    print("[Audit] Primary instance:", primary_id)

    try:
        request_id = request_promotion(state_dir)
    except (CheckpointError, OSError) as error:
        print("[FAIL] Could not create promotion request:", error)
        return

    print("[Audit] Sent false promotion request:", request_id)
    print("[Audit] Waiting", wait_seconds, "seconds.")
    print("[Expected] Standby should print [Promotion Refused].")

    time.sleep(wait_seconds)

    after = get_health(health_url)

    if (
        after is not None
        and after.get("role") == "primary"
        and after.get("instance_id") == primary_id
    ):
        print("[PASS] Original primary is still active.")
        print("[PASS] No split-brain promotion occurred.")
    else:
        print("[FAIL] Primary changed role, changed instance, or stopped.")
        print("Observed health result:", after)


def tamper_checkpoint_test(state_dir, wait_seconds):
    """
    Backs up a real checkpoint and replaces it with invalid data.

    Run only after the primary has crashed. The standby should refuse to
    recover from the corrupted checkpoint.
    """
    checkpoint_path = state_dir / "checkpoint.json"
    backup_path = state_dir / BACKUP_NAME

    if not checkpoint_path.exists():
        print("[FAIL] No checkpoint exists at:", checkpoint_path)
        return

    if backup_path.exists():
        print("[FAIL] Backup already exists:", backup_path)
        print("Restore it before running this test again.")
        return

    backup_path.write_bytes(checkpoint_path.read_bytes())

    checkpoint_path.write_text(
        '{"audit": "checkpoint intentionally corrupted"}\n',
        encoding="utf-8"
    )

    print("[Audit] Original checkpoint backed up to:", backup_path)
    print("[Audit] Checkpoint intentionally corrupted.")
    print("[Expected] Standby should print [Promotion Refused].")
    print("[Expected] Monitor should print [Recovery Failed].")
    print("Wait", wait_seconds, "seconds to observe the result.")
    print("Then restore the original checkpoint with restore-checkpoint.")

    time.sleep(wait_seconds)


def restore_checkpoint(state_dir):
    """Restore the checkpoint saved before the tampering test."""
    checkpoint_path = state_dir / "checkpoint.json"
    backup_path = state_dir / BACKUP_NAME

    if not backup_path.exists():
        print("[FAIL] No audit backup exists at:", backup_path)
        return

    checkpoint_path.write_bytes(backup_path.read_bytes())
    backup_path.unlink()

    print("[Audit] Original checkpoint restored.")


def main():
    parser = argparse.ArgumentParser(
        description="CS456 Part 2 authorized recovery audit utility."
    )

    parser.add_argument(
        "mode",
        choices=[
            "false-failover",
            "tamper-checkpoint",
            "restore-checkpoint"
        ]
    )

    parser.add_argument(
        "--state-dir",
        type=Path,
        default=DEFAULT_STATE_DIR
    )

    parser.add_argument(
        "--health-url",
        default="http://127.0.0.1:8000/health"
    )

    parser.add_argument(
        "--wait",
        type=float,
        default=4.0
    )

    args = parser.parse_args()

    if args.mode == "false-failover":
        false_failover_test(
            args.state_dir,
            args.health_url,
            args.wait
        )

    elif args.mode == "tamper-checkpoint":
        tamper_checkpoint_test(
            args.state_dir,
            args.wait
        )

    else:
        restore_checkpoint(args.state_dir)


if __name__ == "__main__":
    main()