#!/usr/bin/env python
from __future__ import print_function

import os
import pty
import select
import sys
import time


def usage(message=None):
    if message:
        sys.stderr.write("ERROR: %s\n" % message)
    sys.stderr.write("usage: neutron_aria_cirros_guest_exec.py <ip> <command>\n")
    return 64


def read_password():
    path = os.environ.get("CIRROS_PASSWORD_FILE", "")
    if not path:
        raise ValueError("CIRROS_PASSWORD_FILE is required")
    mode = os.stat(path).st_mode & 0o777
    if mode & 0o077:
        raise ValueError("CIRROS_PASSWORD_FILE must have mode 0600")
    with open(path) as handle:
        value = handle.read().strip()
    if not value:
        raise ValueError("CIRROS password file is empty")
    return value


def run_guest(ip, command, password):
    ssh_command = [
        "ssh",
        "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        "-o", "ConnectTimeout=8",
        "-o", "ServerAliveInterval=5",
        "-o", "ServerAliveCountMax=1",
        "-o", "LogLevel=ERROR",
        "cirros@%s" % ip,
        command,
    ]
    pid, fd = pty.fork()
    if pid == 0:
        os.execvp(ssh_command[0], ssh_command)

    output = b""
    sent_password = False
    deadline = time.time() + 45
    while time.time() < deadline:
        readable, _, _ = select.select([fd], [], [], 0.5)
        if not readable:
            continue
        try:
            chunk = os.read(fd, 4096)
        except OSError:
            break
        if not chunk:
            break
        lowered = chunk.lower()
        if b"password:" in lowered:
            if sent_password:
                os.kill(pid, 15)
                return 1, output
            os.write(fd, (password + "\n").encode("utf-8"))
            sent_password = True
            continue
        output += chunk

    _waited, status = os.waitpid(pid, 0)
    exit_code = os.WEXITSTATUS(status) if os.WIFEXITED(status) else 1
    return exit_code, output


def main(argv):
    if len(argv) != 3:
        return usage()
    try:
        password = read_password()
    except (IOError, OSError, ValueError) as error:
        return usage(str(error))
    exit_code, output = run_guest(argv[1], argv[2], password)
    sys.stdout.write(output.decode("utf-8", "replace"))
    return exit_code


if __name__ == "__main__":
    sys.exit(main(sys.argv))
