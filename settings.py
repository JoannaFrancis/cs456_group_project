from pathlib import Path

# Shared default regardless of terminal working directory.
DEFAULT_STATE_DIR = Path(__file__).resolve().parent / 'state'
