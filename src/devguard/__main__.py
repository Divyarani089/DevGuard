"""Allow running DevGuard with python -m devguard."""

from .cli import main


if __name__ == "__main__":
    raise SystemExit(main())
