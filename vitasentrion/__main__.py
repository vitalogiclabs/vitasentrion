"""Allow running the CLI via `python -m vitasentrion`."""
import sys

from vitasentrion.cli import main

if __name__ == "__main__":
    sys.exit(main())
