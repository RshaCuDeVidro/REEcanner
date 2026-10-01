"""setuptools shim: compile worker.so as part of the build.

pyproject.toml declares static metadata; this file exists only so that
`pip install .` / `pipx install .` (which go through the setuptools PEP 517
backend) compile the C worker before the wheel is assembled. Without it,
installs silently fall back to the slower pure-Python engine.
"""

import subprocess
from pathlib import Path

from setuptools import setup
from setuptools.command.build_py import build_py

ROOT = Path(__file__).parent


class BuildPyWithWorker(build_py):
    def run(self):
        src = ROOT / "reecanner" / "worker.c"
        out = ROOT / "reecanner" / "worker.so"
        if src.exists() and (
            not out.exists() or out.stat().st_mtime < src.stat().st_mtime
        ):
            subprocess.run(["make"], cwd=ROOT, check=True)
        super().run()


setup(cmdclass={"build_py": BuildPyWithWorker})
