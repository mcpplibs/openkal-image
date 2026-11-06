"""Linux sanitizer controls for debugger objects and announcement ownership."""
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
import argparse
import os
import re
import subprocess
import tempfile

parser = argparse.ArgumentParser()
parser.add_argument('--cxx', required=True)
parser.add_argument('--jobs', type=int, default=2, choices=[1, 2])
args = parser.parse_args()
root = Path(__file__).resolve().parents[2]
tests = root / '.github/tests'
sanitizers = ['-fsanitize=address,undefined', '-fno-omit-frame-pointer']
includes = ['-I', str(root / 'ld/include'), '-I', str(root / 'ld/src')]


def execute(command, label, directory, environment=None):
    result = subprocess.run(command, cwd=directory, env=environment,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    (directory / (label + '.log')).write_text(result.stdout)
    if result.returncode:
        print(result.stdout)
        raise RuntimeError(label + ' failed with exit ' + str(result.returncode))
    return result.stdout


with tempfile.TemporaryDirectory(prefix='okld-debugger-contract-', dir=os.environ.get('RUNNER_TEMP')) as scratch:
    work = Path(scratch)
    (work / 'fixtures').mkdir()
    sources = sorted((root / 'ld/src').glob('*.cpp'))
    compile_jobs = []
    library_objects = []
    for source in sources:
        target = work / ('lib-' + source.stem + '.o')
        library_objects.append(str(target))
        command = [args.cxx, '-std=c++20', '-O1', '-g', *sanitizers, *includes,
                   '-fno-exceptions', '-fno-rtti', '-fno-stack-protector',
                   '-c', str(source), '-o', str(target)]
        compile_jobs.append((command, target.stem))
    for name in ['builder', 'loader']:
        command = [args.cxx, '-std=c++20', '-O1', '-g', *sanitizers, *includes,
                   '-c', str(tests / ('debug-image-' + name + '.cpp')),
                   '-o', str(work / (name + '.o'))]
        compile_jobs.append((command, name))

    def compile_one(job):
        command, label = job
        execute(command, label, work)

    with ThreadPoolExecutor(max_workers=args.jobs) as pool:
        list(pool.map(compile_one, compile_jobs))

    fixture_flags = ['-std=c++17', '-O0', '-fPIC', '-ffreestanding', '-fno-exceptions',
                     '-fno-rtti', '-fno-stack-protector', '-nostdlib', '-shared', '-fuse-ld=lld']
    source = tests / 'debug-loader'
    note = str(source / 'note.S')
    common_link = ['-Wl,--hash-style=sysv,-z,max-page-size=65536']

    def dependency(name):
        command = [args.cxx, *fixture_flags, str(source / (name + '.cpp')), note,
                   '-Wl,-soname,' + name + '.oke,-e,' + name.replace('-', '_'),
                   *common_link, '-o', str(work / 'fixtures' / (name + '.oke'))]
        execute(command, name, work)

    with ThreadPoolExecutor(max_workers=args.jobs) as pool:
        list(pool.map(dependency, ['dep-a', 'dep-b']))
    for name, retained in [('main-no-relocs', False), ('main-good', True)]:
        command = [args.cxx, *fixture_flags, '-g', str(source / 'main.cpp'), note,
                   '-L', str(work / 'fixtures'), '-Wl,-e,program,--no-as-needed', *common_link]
        if retained:
            command += ['-Wl,--emit-relocs']
        command += ['-l:dep-a.oke', '-l:dep-b.oke', '-o', str(work / 'fixtures' / (name + '.oke'))]
        execute(command, name, work)
    execute([args.cxx, *fixture_flags, str(source / 'dep-a-shared.cpp'), note,
             '-L', str(work / 'fixtures'), '-Wl,-soname,dep-a.oke,-e,dep_a,--no-as-needed',
             *common_link, '-l:dep-b.oke', '-o', str(work / 'fixtures/dep-a-shared.oke')],
            'dep-a-shared', work)

    environment = os.environ.copy()
    environment.update(ASAN_OPTIONS='detect_leaks=1', UBSAN_OPTIONS='halt_on_error=1')
    for name in ['builder', 'loader']:
        binary = work / name
        execute([args.cxx, *sanitizers, str(work / (name + '.o')), *library_objects, '-o', str(binary)],
                name + '-link', work)
        output = execute([str(binary)], name + '-run', work, environment)
        result = re.search(r'RESULT (\d+) passed (\d+) failed', output)
        if not result or int(result[1]) == 0 or int(result[2]) != 0:
            raise RuntimeError(name + ' did not complete its assertions')
        print(name + ': ' + result[1] + ' cases passed with address/undefined/leak sanitizers')
