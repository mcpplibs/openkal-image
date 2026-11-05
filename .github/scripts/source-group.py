"""Select matching specification/backend source for a coordinated pull request."""
from pathlib import Path
import os
import re
import subprocess
import sys

branch = sys.argv[1]
backend = {"Linux": "openkal-linux", "macOS": "openkal-macos", "Windows": "openkal-windows"}[os.environ["RUNNER_OS"]]
root = Path.cwd()
deps = root / ".ci-deps"
deps.mkdir(exist_ok=True)
manifest = root / "run/mcpp.toml"
text = manifest.read_text()
for package in ["openkal", backend]:
    path = deps / package
    subprocess.run(["git", "clone", "--quiet", "https://github.com/mcpplibs/" + package, str(path)], check=True)
    selected = subprocess.run(["git", "-C", str(path), "rev-parse", "--verify", "origin/" + branch], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if selected.returncode == 0:
        subprocess.run(["git", "-C", str(path), "checkout", "--quiet", "origin/" + branch], check=True)
    requested = re.search(r"^" + re.escape(package) + r'\s*=\s*"([0-9.]+)"', text, re.M)
    actual = re.search(r'^version\s*=\s*"([0-9.]+)"', (path / "mcpp.toml").read_text(), re.M)
    if not requested or not actual or requested[1] != actual[1]:
        raise SystemExit(package + ": the selected source and declared version are not in step")
    revision = subprocess.check_output(["git", "-C", str(path), "rev-parse", "HEAD"], text=True).strip()
    print(package, actual[1], revision, flush=True)
    native = path.as_posix()
    text = re.sub(r"^" + re.escape(package) + r"\s*=.*$", lambda _: package + ' = { path = "' + native + '" }', text, flags=re.M)
manifest.write_text(text)
implementation = deps / backend / "mcpp.toml"
implementation.write_text(re.sub(r"^openkal\s*=.*$", 'openkal = { path = "../openkal" }', implementation.read_text(), flags=re.M))
with Path(os.environ["GITHUB_ENV"]).open("a") as env:
    env.write("OPENKAL_INCLUDE=" + (deps / "openkal/include").as_posix() + "\n")
