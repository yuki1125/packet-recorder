import subprocess
import sys
from .cli import parse_args
from .recorder import run


def main(argv=None):
    config = parse_args(argv)
    try:
        return run(config)
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        print(f"Recorder error: {exc}", file=sys.stderr)
        if isinstance(exc, subprocess.CalledProcessError) and exc.stderr:
            print(exc.stderr, file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
