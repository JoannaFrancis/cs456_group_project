"""Create a new checkpoint-signing key once before starting primary/standby."""
import argparse
from checkpoint import initialize_state
from settings import DEFAULT_STATE_DIR

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--state-dir', default=DEFAULT_STATE_DIR)
    args = parser.parse_args()
    try:
        path = initialize_state(args.state_dir)
        print('Initialized state signing key:', path)
    except FileExistsError:
        parser.exit(1, 'Key already exists; keeping it unchanged. Setup is already complete.\n')
