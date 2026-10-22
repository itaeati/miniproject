#!/usr/bin/env python3
"""Entry point kept at its original path. The engine lives in the hdf package.

  python3 hypothesis_drilldown_forensics.py run <evidence dir> --config hdf.toml
  python3 hypothesis_drilldown_forensics.py verify <run dir> --config hdf.toml

The previous single-file version is kept as
hypothesis_drilldown_forensics.py.bak-20261007-antigravity.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from hdf.cli import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
