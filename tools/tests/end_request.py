"""A request to end names the openkal call each task of an image waits in (0.7.0).

okrun runs examples/ending, whose main task joins another that waits upon a
word, and is asked to end (SIGTERM; on Windows CTRL_BREAK_EVENT to its process
group): its error stream names each task the image printed --- the main task in
kal_task_join, the other in kal_task_wait --- and the program ends as the
request would have ended it. With `takes' the image took the requests over: the
record names kal_task_wait and kal_time_sleep, and the image ends by itself with
its own status, 7."""
import argparse
import os
from pathlib import Path
import re
import signal
import subprocess
import threading
import time

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--okrun', required=True, type=Path)
parser.add_argument('--image', required=True, type=Path)
args = parser.parse_args()
windows = os.name == 'nt'
# What a request to end leaves of a program that did not take it over: the
# signal, or the status Windows records for a console interrupt
# (STATUS_CONTROL_C_EXIT).
ended_as_requested = 0xC000013A if windows else -signal.SIGTERM


def ask_to_end(*extra):
    flags = subprocess.CREATE_NEW_PROCESS_GROUP if windows else 0
    child = subprocess.Popen([str(args.okrun), str(args.image), *extra], stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, creationflags=flags)
    out, err = [], []
    said = threading.Event()

    def read_out():
        for line in child.stdout:
            out.append(line.decode().replace('\r', ''))
            said.set()

    def read_err():
        err.append(child.stderr.read().decode().replace('\r', ''))

    readers = [threading.Thread(target=f, daemon=True) for f in (read_out, read_err)]
    for reader in readers:
        reader.start()
    if not said.wait(timeout=60):
        child.kill()
        raise AssertionError('the image said nothing in a minute')
    tasks = re.fullmatch(r'ending: main (\d+), other (\d+)', out[0].strip())
    assert tasks, out[0]
    # The other task has begun and the main task has said so: each is a moment
    # from the call it waits in.
    time.sleep(0.5)
    child.send_signal(signal.CTRL_BREAK_EVENT if windows else signal.SIGTERM)
    try:
        status = child.wait(timeout=60)
    except subprocess.TimeoutExpired:
        child.kill()
        raise AssertionError('asked to end, the program had not ended in a minute')
    for reader in readers:
        reader.join(timeout=10)
    record = ''.join(err)
    print(record, end='')
    return status, tasks.group(1), tasks.group(2), ''.join(out), record


status, main, other, out, err = ask_to_end()
assert 'okrun: asked to end; the openkal call each task of the image waits in:' in err, err
assert f'okrun:   task {main} (main): kal_task_join' in err, err
assert f'okrun:   task {other}: kal_task_wait' in err, err
assert status == ended_as_requested, (status, ended_as_requested)
print(f'  ok  asked to end, the record names the call of each task, and the program ended as asked ({status})')

status, main, other, out, err = ask_to_end('takes')
assert f'okrun:   task {main} (main): kal_task_wait' in err, err
assert f'okrun:   task {other}: kal_time_sleep' in err, err
assert 'ending: asked to end, and the image ends by itself' in out, out
assert status == 7, status
print('  ok  an image that took the requests over is named the same, and ends by itself (7)')
