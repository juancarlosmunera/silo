import os
import sys

# `python -m silo` puts the current directory first on the import path, and silo is routinely run
# next to files it does not trust. Drop it before importing anything else, so that a `json.py`
# planted in a model directory is not picked up. This cannot help against a planted `silo.py` or
# `runpy.py`, which would be imported before this file ever runs: from an untrusted directory use
# the installed `silo` command or `bin/silo`, never `python -m silo`.
_cwd = os.getcwd()
sys.path[:] = [p for p in sys.path if p not in ("", ".") and os.path.abspath(p) != _cwd]

from silo.cli import main  # noqa: E402

raise SystemExit(main())
