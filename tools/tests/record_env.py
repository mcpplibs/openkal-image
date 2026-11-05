"""Exercise the native record wrapper's child environment and exit status."""
import argparse
import os
from pathlib import Path
import subprocess
import sys
import tempfile

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--okprof', required=True, type=Path)
args = parser.parse_args()
okprof = args.okprof.resolve().as_posix()
python = Path(sys.executable).resolve().as_posix()
env = os.environ.copy()
env.update(OKPROF_ENV_VALUE='spaces and=equals', OKPROF_ENV_EMPTY='',
           OKRUN_PROF='this value must be replaced')
child = (
    'import os,sys; '
    'assert os.environ.get("OKPROF_ENV_VALUE") == "spaces and=equals"; '
    'assert os.environ.get("OKPROF_ENV_EMPTY", "missing") == ""; '
    'assert os.environ.get("OKRUN_PROF", "").startswith("calls,counters:"); '
    'print("record passed values, empty entries and its profiling setting"); '
    'sys.exit(int(sys.argv[1]))'
)
with tempfile.TemporaryDirectory(prefix='okprof-record-') as directory:
    for status in (0, 23):
        result = subprocess.run(
            [okprof, 'record', '-o', Path(directory).as_posix(), '--',
             python, '-c', child, str(status)],
            env=env, text=True, capture_output=True, timeout=30)
        assert result.returncode == status, (result.returncode, result.stdout, result.stderr)
        assert 'record passed values, empty entries and its profiling setting' in result.stdout
print('okprof record: inherited values, empty values, profiling override and child status held')
