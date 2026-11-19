"""Under a debugger, a program ends as its image ends it (0.7.1).

okrun waits for the requests to end on a task of its own (0.7.0,
run/src/waits.cpp). GDB, stopped while that task waits and then continued,
resumes each task in turn: where the first ended the program before GDB resumed
the other, GDB stopped with "Couldn't get registers: No such process" instead
of reporting the program's end. From 0.7.1 the runner's task returns before the
runner ends the program. Each image is run `--runs' times under GDB, stopped
before the program's end, stepped off the stop and continued: examples/hello,
whose main returns after joining its tasks (the stop: `okld_finalise'), and
examples/exits, whose main calls kal_exit (the stop: the runner's
`own_kal_exit'). Every run ends normally (measured with GDB 15 on Linux x86-64:
20 of 20 for each image under 0.7.1; 1 of 12 for each under 0.7.0)."""
import argparse
from pathlib import Path
import re
import subprocess
import tempfile

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--okrun', required=True, type=Path)
parser.add_argument('--images', required=True, type=Path, help='the directory of hello.oke and exits.oke')
parser.add_argument('--runs', type=int, default=20)
args = parser.parse_args()

stops = [
    ('hello.oke', 'okld_finalise'),
    ('exits.oke', "'okrun::(anonymous namespace)::own_kal_exit(int)'"),
]

with tempfile.TemporaryDirectory() as work:
    for image, stop in stops:
        commands = Path(work) / f'{image}.gdb'
        commands.write_text('\n'.join([
            'set pagination off',
            'set confirm off',
            f'break {stop}',
            'run',
            'info threads',
            # Off the breakpoint, as after a step: GDB continues the stopped
            # task first and then the others, rather than stepping it over the
            # breakpoint alone.
            'stepi',
            'continue',
        ]) + '\n')
        for run in range(args.runs):
            done = subprocess.run(['gdb', '--nx', '--quiet', '--batch', '-x', str(commands),
                                   '--args', str(args.okrun), str(args.images / image)],
                                  stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=120)
            log = done.stdout.decode(errors='replace')
            # The stop is reached with the runner's task beside the image's, so
            # the continuation resumes more than one.
            assert 'Breakpoint 1, ' in log, log
            tasks = re.findall(r'^\*?\s+\d+\s+(?:Thread|LWP)\s', log, re.MULTILINE)
            assert len(tasks) >= 2, log
            assert 'exited normally' in log, f'{image}, run {run + 1} of {args.runs}:\n{log}'
        print(f'  ok  {image}: continued from {stop}, every one of {args.runs} runs ended normally')
