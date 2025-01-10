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

logger = logging.getLogger(__name__)

class ConfigTask:
    def __init__(self, task_def, session):
        if not isinstance(task_def, dict):
            raise ValueError("Invalid task definition passed to ConfigTask")

        if not isinstance(session, obslib.Session):
            raise ValueError("Invalid session passed to ConfigTask")

        # Save the session
        self.session = session

        # Extract common properties
        creates = obslib.extract_property(task_def, "creates", optional=True, default=None)
        creates = session.resolve(creates, (str, type(None)))
        if creates == "":
            creates = None

        # Make sure there is only a single key defined on the task now
        if len(task_def.keys()) != 1:
            raise ValueError(f"Invalid number of tasks/keys defined on task. Must be one: {task_def.keys()}")

        # Extract the task value from the task definition
        task_name = list(task_def.keys())[0]
        if task_name == "exec":
            task_value = obslib.extract_property(task_def, "exec")
            task_value = obslib.resolve(task_value, str)
        elif task_name == "content":
            task_value = obslib.extract_property(task_def, "content")
            task_value = obslib.resolve(task_value, str)
        else:
            raise ValueError(f"Invalid task name defined on task: {task_name}")
        
        self.creates = creates
        self.task_name = task_name
        self.task_value = task_value

    def run(self):
        # Check if there is a creates clause for this task
        if self.creates is not None:
            if os.path.exists(self.creates):
                return

        if self.task_name == "exec":
            # We'll execute the task value and check the return value
            logger.debug("exec")
        elif self.task_name == "content":
            # We'll check the content for the target and update if it is different
            # than what we want to write to it
            # The write is conditional so we can preserve the timestamp on the file, which
            # could be used for something else later
            logger.debug("content")
        else:
            raise ValueError(f"Invalid task name for task: {task_name}")

class QSVMSession():
    def __init__(self, path, vmname):

        # Check incoming arguments
        if not isinstance(path, str) or path == "":
            raise ValueError("Invalid path passed to QSVMSession")

        if not isinstance(vmname, str) or vmname == "":
            raise ValueError("Invalid vmname passed to QSVMSession")

        # Config paths
        qsvm_config_path = os.path.join(path, "qsvm.yaml")
        vm_config_path = os.path.join(path, vmname, "config.yaml")

        # Read qsvm configuration
        # Default to an empty dict if the configuration is not present
        qsvm_config = {}
        try:
            with open(qsvm_config_path) as file:
                qsvm_config = yaml.safe_load(file)
        except FileNotFoundError as e:
            logger.debug(f"Common configuration not found: {qsvm_config_path}")

        # Validate top level format
        if not isinstance(qsvm_config, dict):
            raise ValueError("QSVM configuration must be a dictionary at top level")

        # Read the VM configuration
        with open(vm_config_path) as file:
            vm_config = yaml.safe_load(file)

        # Validate top level format
        if not isinstance(vm_config, dict):
            raise ValueError("VM configuration must be a dictionary at top level")

        # Extract configuration vars
        qsvm_vars = obslib.extract_property(qsvm_config, "vars", optional=True, default={})
        qsvm_vars = obslib.coerce_value(qsvm_vars, (dict, type(None)))
        if qsvm_vars is None:
            qsvm_vars = {}

        vm_vars = obslib.extract_property(vm_config, "vars", optional=True, default={})
        vm_vars = obslib.coerce_value(vm_vars, (dict, type(None)))
        if vm_vars is None:
            vm_vars = {}

        # Merge vars, with vm vars taking precedence
        config_vars = {}
        config_vars.update(qsvm_vars)
        config_vars.update(vm_vars)

        # Add standard vars
        vm_vars["qsvm"] = {
            "vmname": vmname,
            "config_path": vm_config_path
        }

        vm_vars["env"] = os.environ.copy()

        # Resolve reference in config vars and create a session to allow var reference resolving
        config_vars = obslib.eval_vars(config_vars)
        session = obslib.Session(template_vars=vm_vars)

        # Extract working directory configuration
        # 'None' means use the VM directory as working dir. Empty string is converted to None
        workingdir = obslib.extract_property(qsvm_config, "workingdir", optional=True, default=None)
        workingdir = obslib.coerce_value(workingdir, (str, type(None)))
        if workingdir == "":
            workingdir = None

        vm_workingdir = obslib.extract_property(vm_config, "workingdir", optional=True, default=None)
        vm_workingdir = obslib.coerce_value(vm_workingdir, (str, type(None)))
        if vm_workingdir is not None and vm_workingdir != "":
            workingdir = vm_workingdir

        if workingdir is not None:
            workingdir = session.resolve(workingdir)

        if workingdir is None or workingdir == "":
            workingdir = os.path.join(path, vmname)

        # Extract exec command
        exec_cmd = obslib.extract_property(vm_config, "exec")
        exec_cmd = session.resolve(exec_cmd, str)

        # Extract prestart command
        prestart = obslib.extract_property(content, "prestart", optional=True, default=[])
        prestart = obslib.coerce_value(prestart, (list, type(None)))
        if prestart is None:
            prestart = []

        prestart = [ConfigTask(x, session) for x in prestart]

        # Extract poststart command
        poststart = obslib.extract_property(content, "poststart", optional=True, default=[])
        poststart = obslib.coerce_value(poststart, (list, type(None)))
        if poststart is None:
            poststart = []

        poststart = [ConfigTask(x, session) for x in poststart]

        # Extract prestop commands
        prestop = obslib.extract_property(content, "prestop", optional=True, default=[])
        prestop = obslib.coerce_value(prestop, (list, type(None)))
        if prestop is None:
            prestop = []

        prestop = [ConfigTask(x, session) for x in prestop]

        # Extract poststop commands
        poststop = obslib.extract_property(content, "poststop", optional=True, default=[])
        poststop = obslib.coerce_value(poststop, (list, type(None)))
        if poststop is None:
            poststop = []

        poststop = [ConfigTask(x, session) for x in poststop]

        # Make sure there are no other keys left
        if len(content.keys()) > 0:
            raise ValueError(f"Unknown keys in VM configuration: {content.keys()}")

        # Change to the working directory
        if not os.path.exists(workingdir):
            os.makedirs(workingdir)

        os.chdir(workingdir)

        # Properties for the config object
        self.config_vars = config_vars
        self.workingdir = workingdir
        self.exec_cmd = exec_cmd

        self.prestart = prestart
        self.poststart = poststart
        self.prestop = prestop
        self.poststop = poststop


def run_systemctl(user, args):

    cmd = ["systemctl"]
    if user:
        cmd.append("--user")

    cmd = cmd + args

    logger.debug(f"Calling systemctl: {shlex.join(cmd)}")
    ret = subprocess.run(cmd, check=True)

    return 0

def process_install(args):

    target = "network.target"
    cmd = __file__
    if args.user:
        target = "default.target"
        cmd = cmd + " --user"

    cmd = cmd + f" --svc {args.svc} --config {args.config} -v "

    unit_content = textwrap.dedent(f"""\
    [Unit]
    Description=QEMU Systemd Virtual Machine
    Wants={target}
    After={target}

    [Service]
    Type=exec

    ExecStartPre={cmd} internal-prestart-vm %i
    ExecStart={cmd} internal-start-vm %i
    ExecStartPost={cmd} internal-poststart-vm %i

    ExecStop={cmd} internal-prestop-vm %i
    ExecStop={cmd} internal-stop-vm %i $MAINPID
    ExecStopPost={cmd} internal-poststop-vm %i

    Restart=on-failure

    [Install]
    WantedBy={target}
    """)

    # Are we just displaying the unit content?
    if args.stdout:
        print(unit_content)
        return 0

    # Determine systemd unit location
    unit_location = f"/etc/systemd/system/{args.svc}@.service"
    if args.user:
        # Create the user unit path directory, if it doesn't exist
        unit_path = "~/.config/systemd/user"
        if not os.path.exists(unit_path):
            os.makedirs(unit_path)

        unit_location = os.path.expanduser(os.path.join(unit_path, f"{args.svc}@.service"))

    logger.debug(f"Systemd unit location: {unit_location}")

    # Write systemd unit file
    with open(unit_location, "w") as file:
        file.write(unit_content)

    # Reload systemd units, if requested
    if args.reload:
        logger.debug("Reloading systemd units")
        run_systemctl(args.user, ["daemon-reload"])
    else:
        logger.debug("Not performing systemd daemon reload")

    return 0

def process_create(args):

    # Path to configuration
    vm_config_dir = os.path.join(args.config, args.vm)
    if not os.path.exists(vm_config_dir):
        os.makedirs(vm_config_dir)

    vm_config_path = os.path.join(vm_config_dir, "config.yaml")
    logger.debug(f"VM Config Path: {vm_config_path}")

    # Sample/starter configuration
    vm_config = textwrap.dedent(f"""\
    ---
    # Command to run to start the VM
    exec: >
        /usr/bin/qemu-system-x86_64
        -enable-kvm
        -cpu host
        -m 4G
        -smp sockets=1,cores=2,threads=2
        -nographic
    """)

    # Are we just displaying to stdout?
    if args.stdout:
        print(vm_config)
        return 0

    # Check if the configuration is already present
    if not args.force and os.path.exists(vm_config_path):
        logger.error("VM Configuration already exists")
        return 1

    # Write content to configuration file
    with open(vm_config_path, "w") as file:
        logger.debug("Writing vm configuration")
        file.write(vm_config)

    return 0

def process_internal_stop_vm(args):

    # Process to stop
    pid = args.pid

    # Read the VM configuration
    vm_session = QSVMSession(args.config, args.vm)

    # Make sure the process exists
    if not psutil.pid_exists(pid):
        logger.error(f"PID for qemu process does not exist: {pid}")
        return 1

    # Attempt to stop the process with SIGINT
    os.kill(pid, signal.SIGINT)

    # Wait for the process to exit
    for i in range(60):
        if not psutil.pid_exists(pid):
            break

        time.sleep(1)

    # Finish here if the process exited
    if not psutil.pid_exists(pid):
        logger.info(f"Process ({pid}) has exited from SIGINT")
        return 0

    # Process is still active - send kill signal
    os.kill(pid, signal.SIGKILL)

    # Wait for the process to exit
    for i in range(15):
        if not psutil.pid_exists(pid):
            break

        time.sleep(1)

    # Finish here if the process exited
    if not psutil.pid_exists(pid):
        logger.info(f"Process ({pid}) has exited from SIGKILL.")
        return 0

    # Shouldn't still be alive after a SIGKILL
    logger.error(f"Process ({pid}) did not exit from SIGINT or SIGKILL")
    return 1

def process_internal_start_vm(args):

    # Read the VM configuration
    vm_session = QSVMSession(args.config, args.vm)

    # Start the VM
    exec_args = shlex.split(vm_session.exec_cmd)
    logger.debug(f"Exec: {exec_args}")
    os.execvp(exec_args[0], exec_args)

    # Shouldn't get here unless the execvp call failed
    logger.error("Exec call failed or returned")
    return 1

def process_internal_prestart_vm(args):

    # Read the VM configuration
    vm_session = QSVMSession(args.config, args.vm)

    # Run the tasks
    for task_def in vm_session.prestart:
        if task.run(args) != 0:
            return 1

    return 0

def process_internal_poststart_vm(args):

    # Read the VM configuration
    vm_session = QSVMSession(args.config, args.vm)

    # Run the tasks
    for task_def in vm_session.poststart:
        if task.run(args) != 0:
            return 1

    return 0

def process_internal_prestop_vm(args):

    # Read the VM configuration
    vm_session = QSVMSession(args.config, args.vm)

    # Run the tasks
    for task_def in vm_session.prestop:
        if task.run(args) != 0:
            return 1

    return 0

def process_internal_poststop_vm(args):

    # Read the VM configuration
    vm_session = QSVMSession(args.config, args.vm)

    # Run the tasks
    for task_def in vm_session.poststop:
        if task.run(args) != 0:
            return 1

    return 0

def process_start(args):
    return run_systemctl(args.user, ["start", f"{args.svc}@{args.vm}"])

def process_stop(args):
    return run_systemctl(args.user, ["stop", f"{args.svc}@{args.vm}"])

def process_enable(args):
    return run_systemctl(args.user, ["enable", f"{args.svc}@{args.vm}"])

def process_disable(args):
    return run_systemctl(args.user, ["disable", f"{args.svc}@{args.vm}"])


def process_args():
    parser = argparse.ArgumentParser(
        prog="qsvm", description="QEMU Systemd VM", exit_on_error=False
    )

    # Common arguments
    parser.add_argument("-v", "-d", action="store_true", dest="verbose", help="Enable verbose output")

    parser.add_argument("--user", action="store_true", dest="user", help="Use systemd user services")

    parser.add_argument("--config", default=None, help="Configuration directory")

    parser.add_argument("--svc", default="qsvm", help="Systemd service name")

    parser.set_defaults(call_func=None)

    subparsers = parser.add_subparsers(dest="subcommand")

    # Install subcommand
    sub_install = subparsers.add_parser("install", help="Install the systemd service")
    sub_install.set_defaults(call_func=process_install)

    group = sub_install.add_mutually_exclusive_group(required=False)

    group.add_argument("--stdout", action="store_true", default=False, help="Generate systemd unit content on stdout")

    group.add_argument("--reload", action="store_true", default=False, help="Perform a systemctl daemon-reload")

    # Create subcommand
    sub_create = subparsers.add_parser("create", help="Create a sample VM definition")
    sub_create.set_defaults(call_func=process_create)

    sub_create.add_argument("--stdout", action="store_true", default=False, help="Generate VM definition on stdout")

    sub_create.add_argument("--force", action="store_true", default=False, help="Force creation of VM configuration file - ignore if present")

    sub_create.add_argument("vm", action="store", help="VM name to create")

    # Internal prestart subcommand
    sub_internal_prestart_vm = subparsers.add_parser("internal-prestart-vm", help="Called by systemd unit before starting a VM - Not intended to be called by the user")
    sub_internal_prestart_vm.set_defaults(call_func=process_internal_prestart_vm)

    sub_internal_prestart_vm.add_argument("vm", action="store", help="VM name for prestart")

    # Internal poststart subcommand
    sub_internal_poststart_vm = subparsers.add_parser("internal-poststart-vm", help="Called by systemd unit before starting a VM - Not intended to be called by the user")
    sub_internal_poststart_vm.set_defaults(call_func=process_internal_poststart_vm)

    sub_internal_poststart_vm.add_argument("vm", action="store", help="VM name for poststart")

    # Internal Start subcommand
    sub_internal_start_vm = subparsers.add_parser("internal-start-vm", help="Called by systemd unit to start a VM - Not intended to be called by the user")
    sub_internal_start_vm.set_defaults(call_func=process_internal_start_vm)

    sub_internal_start_vm.add_argument("vm", action="store", help="VM name to start")

    # Internal prestop subcommand
    sub_internal_prestop_vm = subparsers.add_parser("internal-prestop-vm", help="Called by systemd unit before stoping a VM - Not intended to be called by the user")
    sub_internal_prestop_vm.set_defaults(call_func=process_internal_prestop_vm)

    sub_internal_prestop_vm.add_argument("vm", action="store", help="VM name for prestop")

    # Internal poststop subcommand
    sub_internal_poststop_vm = subparsers.add_parser("internal-poststop-vm", help="Called by systemd unit before stoping a VM - Not intended to be called by the user")
    sub_internal_poststop_vm.set_defaults(call_func=process_internal_poststop_vm)

    sub_internal_poststop_vm.add_argument("vm", action="store", help="VM name for poststop")

    # Internal Stop subcommand
    sub_internal_stop_vm = subparsers.add_parser("internal-stop-vm", help="Called by systemd unit to stop a VM - Not intended to be called by the user")
    sub_internal_stop_vm.set_defaults(call_func=process_internal_stop_vm)

    sub_internal_stop_vm.add_argument("vm", action="store", help="VM name to stop")

    sub_internal_stop_vm.add_argument("pid", action="store", type=int, help="PID of qemu process")

    # start command
    sub_start = subparsers.add_parser("start", help="Start a VM using systemd")
    sub_start.set_defaults(call_func=process_start)

    sub_start.add_argument("vm", action="store", help="VM name to start")

    # stop command
    sub_stop = subparsers.add_parser("stop", help="Stop a VM using systemd")
    sub_stop.set_defaults(call_func=process_stop)

    sub_stop.add_argument("vm", action="store", help="VM name to stop")

    # enable command
    sub_enable = subparsers.add_parser("enable", help="Configure a VM to start automatically")
    sub_enable.set_defaults(call_func=process_enable)

    sub_enable.add_argument("vm", action="store", help="VM name to enable")

    # disable command
    sub_disable = subparsers.add_parser("disable", help="Stop a VM from starting automatically")
    sub_disable.set_defaults(call_func=process_disable)

    sub_disable.add_argument("vm", action="store", help="VM name to disable")

    # Parse arguments
    args = parser.parse_args()

    verbose = args.verbose
    subcommand = args.subcommand

    # Configuration directory
    if args.config is None or args.config == "":
        args.config = "/etc/qsvm/"
        if args.user:
            args.config = os.path.expanduser("~/.config/qsvm/")

    # Create the config directory, if it doesn't exist
    if not os.path.exists(args.config):
        os.makedirs(args.config)

    # Logging configuration
    level = logging.INFO
    if verbose:
        level = logging.DEBUG
    logging.basicConfig(level=level, format="%(levelname)s: %(message)s")
    logger = logging.getLogger(__name__)

    if subcommand is None or subcommand == "" or args.call_func is None:
        logger.warning("Missing subcommand")
        return 1

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

