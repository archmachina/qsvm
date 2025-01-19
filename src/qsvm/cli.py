#!/usr/bin/env python3

import os
import sys
import argparse
import logging
import textwrap
import subprocess
import yaml
import shlex
import psutil
import signal
import time
import obslib
import socket
import shutil
import urllib.request
import hashlib

import qsvm.exception as exception
import qsvm.core as core

logger = logging.getLogger(__name__)

def process_args():
    parser = argparse.ArgumentParser(
        prog="qsvm", description="QEMU Systemd VM", exit_on_error=False
    )

    # Common arguments
    parser.add_argument("-v", "-d", action="store_true", dest="verbose", help="Enable verbose output")

    parser.add_argument("--user", action="store_true", dest="user", help="Use systemd user services")

    parser.add_argument("--config", default=None, help="Configuration directory")

    parser.add_argument("--svc", default="qsvm", help="Systemd service name")

    parser.add_argument("--is_svc", action="store_true", help="QSVM is being called from a service - set when called from systemd")

    parser.set_defaults(call_func=None)

    subparsers = parser.add_subparsers(dest="subcommand")

    # Test subcommand
    sub_test = subparsers.add_parser("test", help="Test execute of QSVM - Used internally to test access to QSVM")
    sub_test.set_defaults(call_func=core.process_test)

    # Install subcommand
    sub_install = subparsers.add_parser("install", help="Install the systemd service")
    sub_install.set_defaults(call_func=core.process_install)

    group = sub_install.add_mutually_exclusive_group(required=False)

    group.add_argument("--stdout", action="store_true", default=False, help="Generate systemd unit content on stdout")

    group.add_argument("--reload", action="store_true", default=False, help="Perform a systemctl daemon-reload")

    sub_install.add_argument("--cmd", action="store", default=None, help="Override command line for calling qsvm")

    # Create subcommand
    sub_create = subparsers.add_parser("create", help="Create a sample VM definition")
    sub_create.set_defaults(call_func=core.process_create)

    sub_create.add_argument("--stdout", action="store_true", default=False, help="Generate VM definition on stdout")

    sub_create.add_argument("--force", action="store_true", default=False, help="Force creation of VM configuration file - ignore if present")

    sub_create.add_argument("vm", action="store", help="VM name to create")

    # Internal Start subcommand
    sub_direct_start_vm = subparsers.add_parser("direct-start-vm", help="Start VM directly. Normally called by systemd")
    sub_direct_start_vm.set_defaults(call_func=core.process_direct_start_vm)

    sub_direct_start_vm.add_argument("vm", action="store", help="VM name to start")

    # Internal Stop subcommand
    sub_direct_stop_vm = subparsers.add_parser("direct-stop-vm", help="Direct stop VM by PID. Normally called by systemd")
    sub_direct_stop_vm.set_defaults(call_func=core.process_direct_stop_vm)

    sub_direct_stop_vm.add_argument("vm", action="store", help="VM name to stop")

    sub_direct_stop_vm.add_argument("pid", action="store", type=int, help="PID of qemu process")

    # start command
    sub_start = subparsers.add_parser("start", help="Start a VM using systemd")
    sub_start.set_defaults(call_func=core.process_start)

    sub_start.add_argument("vm", action="store", help="VM name to start")

    # stop command
    sub_stop = subparsers.add_parser("stop", help="Stop a VM using systemd")
    sub_stop.set_defaults(call_func=core.process_stop)

    sub_stop.add_argument("vm", action="store", help="VM name to stop")

    # restart command
    sub_restart = subparsers.add_parser("restart", help="Restart a VM using systemd")
    sub_restart.set_defaults(call_func=core.process_restart)

    sub_restart.add_argument("vm", action="store", help="VM name to restart")

    sub_restart.add_argument("--if_changed", action="store_true", help="Request qemu restart if the configuration has changed")

    # enable command
    sub_enable = subparsers.add_parser("enable", help="Configure a VM to start automatically")
    sub_enable.set_defaults(call_func=core.process_enable)

    sub_enable.add_argument("vm", action="store", help="VM name to enable")

    # disable command
    sub_disable = subparsers.add_parser("disable", help="Stop a VM from starting automatically")
    sub_disable.set_defaults(call_func=core.process_disable)

    sub_disable.add_argument("vm", action="store", help="VM name to disable")

    # Parse arguments
    args = parser.parse_args()

    verbose = args.verbose
    subcommand = args.subcommand

    # Logging configuration
    level = logging.INFO
    if verbose:
        level = logging.DEBUG
    logging.basicConfig(level=level, format="%(levelname)s: %(message)s")
    logger = logging.getLogger(__name__)

    # Exit here if there is no subcommand
    if subcommand is None or subcommand == "" or args.call_func is None:
        logger.warning("Missing subcommand")
        return 1

    # Configuration directory
    if args.config is None or args.config == "":
        args.config = "/etc/qsvm/"
        if args.user:
            args.config = os.path.expanduser("~/.config/qsvm/")

    return args.call_func(args)

def main():
    try:
        ret = process_args()
        sys.stdout.flush()
        sys.exit(ret)
    except argparse.ArgumentError as e:
        logging.getLogger(__name__).warning(e)
        sys.stdout.flush()
        sys.exit(1)
    except Exception as e:
        logging.getLogger(__name__).exception(e)
        sys.stdout.flush()
        sys.exit(1)

if __name__ == "__main__":
    main()

