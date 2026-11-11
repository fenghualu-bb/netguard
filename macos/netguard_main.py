"""Entry point. Run with `python3 -I -B`; the package directory is added explicitly
because isolated mode does not put the script directory on sys.path."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from netguard.cli import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
