"""Lets `python -m secureguard` run the CLI."""
import sys

from secureguard.cli import main

if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))