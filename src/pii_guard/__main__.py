"""Entry point: `uv run python -m pii_guard [command] ...`

Shortcut: if first argument is a file path (not a subcommand), automatically
prepends 'anonymize' for backward-compatible invocation.

    uv run python -m pii_guard input.txt          # → anonymize input.txt
    uv run python -m pii_guard anonymize input.txt
    uv run python -m pii_guard restore output.txt -m mapping.json
    uv run python -m pii_guard serve
"""

from __future__ import annotations

import sys

_SUBCOMMANDS = {"anonymize", "anon", "restore", "serve", "-h", "--help"}


def main() -> None:
    # Auto-prepend 'anonymize' when first positional arg looks like a file path
    if len(sys.argv) >= 2 and sys.argv[1] not in _SUBCOMMANDS and not sys.argv[1].startswith("-"):
        sys.argv.insert(1, "anonymize")

    from pii_guard.cli import build_parser, cmd_anonymize, cmd_restore, cmd_serve

    parser = build_parser()
    args = parser.parse_args()

    if args.command in ("anonymize", "anon"):
        sys.exit(cmd_anonymize(args))
    elif args.command == "restore":
        sys.exit(cmd_restore(args))
    elif args.command == "serve":
        sys.exit(cmd_serve(args))
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
