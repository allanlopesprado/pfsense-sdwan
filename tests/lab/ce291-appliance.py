#!/usr/bin/env python3
"""Boot the exact Netgate userland and install the system offline."""
import os
from pathlib import Path
import shlex
import subprocess
import sys
import time

import pexpect


def run(image):
    log = open("ce291-console.log", "w", encoding="utf-8")
    qemu = pexpect.spawn("qemu-system-x86_64", [
        "-machine", "q35,accel=kvm:tcg", "-m", "2048", "-smp", "2",
        "-drive", f"file={image},format=raw,if=virtio",
        "-display", "none", "-serial", "stdio", "-monitor", "none",
        "-no-reboot", "-nic", "none",
    ], encoding="utf-8", codec_errors="replace", timeout=120)
    qemu.logfile_read = log
    try:
        qemu.expect("Enter full pathname of shell")
        qemu.sendline("")
        qemu.expect(r"# ")
        command(qemu, "mount -uw /")
        output = command(qemu, "uname -a; pkg query '%n %v' pfSense-base pfSense-kernel-pfSense")
        print(output, flush=True)
        if "pfSense-kernel-pfSense 2.9.1" not in output:
            raise AssertionError("Unexpected kernel package")
        command(qemu, "mkdir -p /root/netgate-repos; cp /root/sdwan-lab/pfsense.conf /root/netgate-repos/")
        print(command(qemu, "env ABI=FreeBSD:16:amd64 OSVERSION=1600018 REPOS_DIR=/root/netgate-repos pkg-static install -Uy pfSense pfSense-default-config-serial", timeout=360), flush=True)
        print(command(qemu, "pkg query '%n %v' pfSense pfSense-system pfSense-default-config-serial"), flush=True)
        print("CE_OFFLINE_INSTALL_OK", flush=True)
    finally:
        qemu.terminate(force=True)
        log.close()


def command(qemu, script, timeout=60):
    qemu.sendline("sh -c " + shlex.quote(script) + "; echo __RESULT__$?")
    qemu.expect(r"\r\n__RESULT__(\d+)\r\n", timeout=timeout)
    result = qemu.before.rstrip()
    if qemu.match.group(1) != "0":
        raise RuntimeError(f"{script} failed: {result}")
    return result


if __name__ == "__main__":
    run(Path(sys.argv[1]).resolve())

