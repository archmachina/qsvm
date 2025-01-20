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
import jinja2

import qsvm.exception as exception
import qsvm.util as util
import qsvm.j2helper as j2helper

logger = logging.getLogger(__name__)

ubuntu_sample = """
---

vars:
  address: "192.168.1.0/24"
  gateway: "192.168.1.254"
  dns: "1.1.1.1"
  graphic_opt: "{{ '-nographic' if qsvm.is_svc else '-monitor stdio' }}"
  # Example SSH key
  ssh_authorized_key: "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBNYnsmdUpDPjjCmicJYvDNos2XADUAbJzuI57j81oSJEpX1vKguMhCK1Nfln7Ycm5aKAKi5JESiwHgXwjbI2db0= sample@somewhere"
  initial_size: "20G"
  cloud_image: "https://cloud-images.ubuntu.com/noble/20241210/noble-server-cloudimg-amd64.img"
  interface: "enp0s2"
  mac: "{{ gen_mac([qsvm.vmname]) }}"

  network_config: |
    ---
    version: 2
    ethernets:
      {{ interface }}:
        dhcp4: true
        # addresses: [ "{{ address }}" ]
        nameservers:
          addresses:
            - "{{ dns }}"
        # routes:
        #   - to: 0.0.0.0/0
        #     via: {{ gateway }}

  meta_data: |
    local-hostname: {{ qsvm.vmname }}

  user_data: |
    #cloud-config
    user: ubuntu
    password: "Password12"
    chpasswd:
      expire: False
    users:
      - name: ubuntu
        groups: users, sudo
        shell: /bin/bash
        plain_text_passwd: "Password12"
        ssh_authorized_keys:
          - {{ ssh_authorized_key }}


# If we're called as a service, use qemu-mon for monitor, which
# also allows graceful shutdown. If interactive, disable the monitor
# which allows the Ctrl-A X or Ctrl-A C combinations.
# Default is 'qemu-mon', which unconditionally enables the monitor
# socket.
qemu_mon_path: "{{ 'qemu-mon' if qsvm.is_svc else '' }}"

exec: >
    /usr/bin/qemu-system-x86_64
    -machine type=q35,accel=kvm
    -cpu host
    -m 4G
    -smp sockets=1,cores=2,threads=2
    {{ graphic_opt }}
    -drive if=virtio,format=qcow2,file=root.img
    -drive if=virtio,format=raw,file=cloud-init.img
    -drive if=virtio,format=qcow2,file=data.img
    -netdev user,id=net0,net=192.168.0.0/24,dhcpstart=192.168.0.50
    -device virtio-net-pci,netdev=net0,mac={{ mac }}

prestart:
  - name: Configure drives
    drives:
      items:
        - path: source.img
          url: "{{ cloud_image }}"
        - path: root.img
          copy: source.img
          size: 15G
        - path: data.img
          format: qcow2
          size: 5G

  - name: Copy cloud init network config
    copy:
      path: network-config.yaml
      content: "{{ network_config }}"

  - name: Copy cloud init user data
    copy:
      path: user-data.yaml
      content: "{{ user_data }}"

  - name: Copy cloud init meta data
    copy:
      path: meta-data.yaml
      content: "{{ meta_data }}"

  # Create the cloud-init image on every startup
  - name: Create cloud-init image
    # Uncomment if you only want it to create cloud-init.img, if it's missing
    # creates: cloud-init.img
    exec:
      cmd: >
        cloud-localds -v --network-config=network-config.yaml cloud-init.img user-data.yaml meta-data.yaml

"""

class ConfigTaskExec:
    def __init__(self, definition, parent):
        definition = obslib.coerce_value(definition, dict)

        # Extract cmd property
        self.cmd = obslib.extract_property(definition, "cmd")
        self.cmd = parent.session.resolve(self.cmd, (list, str))

        # cmd should be an array, but a string is allowed. Convert
        # it to an array here
        if isinstance(self.cmd, str):
            self.cmd = [self.cmd]

        # Make sure we have correct types
        for item in self.cmd:
            if not isinstance(item, str) or item == "":
                raise ValueError("Invalid type in exec list. Must be a list of strings or string")

        # Make sure there are no unknown values
        if len(definition.keys()) > 0:
            raise ValueError(f"Invalid keys on exec definition: {definition.keys()}")

    def run(self):
        for cmd_item in self.cmd:
            logger.info(f"Running: {cmd_item}")

            # Run 'cmd' using shell
            sys.stdout.flush()
            ret = subprocess.run(cmd_item, shell=True)
            logger.info(f"Exec: return code {ret.returncode}")

            if ret.returncode != 0:
                logger.error(f"Exec command returned non-zero: {ret.returncode}")
                return 1

        return 0

class ConfigTaskDrivesItem:
    def __init__(self, definition, parent):
        definition = obslib.coerce_value(definition, dict)

        # Extract path property
        self.path = obslib.extract_property(definition, "path")
        self.path = parent.session.resolve(self.path, str)

        # Extract url property
        self.url = obslib.extract_property(definition, "url", optional=True, default=None)
        if self.url is not None:
            self.url = parent.session.resolve(self.url, (str, type(None)))

        # Extract copy property
        self.copy = obslib.extract_property(definition, "copy", optional=True, default=None)
        if self.copy is not None:
            self.copy = parent.session.resolve(self.copy, (str, type(None)))

        # Extract size property
        self.size = obslib.extract_property(definition, "size", optional=True, default=None)
        if self.size is not None:
            self.size = parent.session.resolve(self.size, (str, type(None)))

        # Extract format property
        self.format = obslib.extract_property(definition, "format", optional=True, default="qcow2")

        if self.format is not None:
            self.format = parent.session.resolve(self.format, str)

        if self.format is None or self.format == "":
            raise ValueError("Invalid format on drive specification")

    def run(self):
        logger.info(f"Processing drive task for {self.path}")

        # Check if the image is already present
        if not os.path.exists(self.path):
            if self.url is not None and self.url != "":
                logger.info(f"Downloading {self.url} to {self.path}")
                urllib.request.urlretrieve(self.url, self.path)
            elif self.copy is not None and self.copy != "":
                if not os.path.exists(self.copy):
                    logger.error(f"Source for copy does not exist: {self.copy}")
                    return 1

                logger.info(f"Copying {self.copy} to {self.path}")
                shutil.copy(self.copy, self.path)

        # If 'size' is defined, we update the existing image size or
        # create it, if it doesn't exist
        if self.size is not None and self.size != "":
            if os.path.exists(self.path):
                logger.info(f"Resizing {self.path} to {self.size}")

                sys.stdout.flush()
                ret = subprocess.run([
                    "qemu-img", "resize", self.path, self.size
                ])
            else:
                logger.info(f"Creating image {self.path}")

                sys.stdout.flush()
                ret = subprocess.run([
                    "qemu-img", "create", "-f", self.format, self.path, self.size
                ])

            if ret.returncode != 0:
                logger.error(f"qemu-img returned non zero: {ret.returncode}")
                return 1

        return 0

class ConfigTaskDrives:
    def __init__(self, definition, parent):
        definition = obslib.coerce_value(definition, dict)

        # Extract items property
        self.items = obslib.extract_property(definition, "items")
        self.items = parent.session.resolve(self.items, list)

        # Convert each item to a ConfigTaskDrivesItem object
        self.items = [ConfigTaskDrivesItem(x, parent) for x in self.items]

        # Make sure there are no unknown values
        if len(definition.keys()) > 0:
            raise ValueError(f"Invalid keys on exec definition: {definition.keys()}")

    def run(self):
        for drive_item in self.items:
            if drive_item.run() != 0:
                return 1

        return 0

class ConfigTaskCopy:
    def __init__(self, definition, parent):
        definition = obslib.coerce_value(definition, dict)

        # Extract content property
        self.content = obslib.extract_property(definition, "content")
        self.content = parent.session.resolve(self.content, str)

        # Extract path property
        self.path = obslib.extract_property(definition, "path")
        self.path = parent.session.resolve(self.path, str)

        # Make sure there are no unknown values
        if len(definition.keys()) > 0:
            raise ValueError(f"Invalid keys on exec definition: {definition.keys()}")

    def run(self):

        logger.info(f"Copy: checking content for path: {self.path}")

        # Fail if the target is a directory
        if os.path.isdir(self.path):
            logger.error(f"Target for 'content' is a directory: {self.path}")
            return 1

        # Check content for the target, if it exists
        current_content = None
        if os.path.exists(self.path):
            # Target exists - read content for comparison
            logger.debug("Content: target exists. Reading content")
            with open(self.path, "r") as file:
                current_content = file.read()

        # Determine whether we should write content
        if current_content is None or current_content != self.content:
            logger.debug("Target missing or requires updating. Writing.")

            with open(self.path, "w") as file:
                file.write(self.content)
        else:
            logger.debug("Target did not require updating")

        return 0


class ConfigTask:
    def __init__(self, task_def, session):
        if not isinstance(task_def, dict):
            raise ValueError("Invalid task definition passed to ConfigTask")

        if not isinstance(session, obslib.Session):
            raise ValueError("Invalid session passed to ConfigTask")

        # Save the session
        self.session = session

        # Extract common properties
        self.name = obslib.extract_property(task_def, "name")
        self.name = self.session.resolve(self.name, str)

        self.creates = obslib.extract_property(task_def, "creates", optional=True, default=None)
        if self.creates is not None:
            self.creates = self.session.resolve(self.creates, (str, type(None)))
        if self.creates == "":
            self.creates = None

        # Make sure there is only a single key defined on the task now
        if len(task_def.keys()) != 1:
            raise ValueError(f"Invalid number of tasks/keys defined on task. Must be one: {task_def.keys()}")

        # Extract the task value from the task definition
        task_type = list(task_def.keys())[0]
        if task_type == "exec":
            task_value = obslib.extract_property(task_def, "exec")
            impl = ConfigTaskExec(task_value, self)
        elif task_type == "copy":
            task_value = obslib.extract_property(task_def, "copy")
            impl = ConfigTaskCopy(task_value, self)
        elif task_type == "drives":
            task_value = obslib.extract_property(task_def, "drives")
            impl = ConfigTaskDrives(task_value, self)
        else:
            raise ValueError(f"Invalid task name defined on task: {task_type}")

        self.impl = impl
        self.task_type = task_type

    def run(self):
        # Check if there is a creates clause for this task
        if self.creates is not None:
            if os.path.exists(self.creates):
                return 0

        logger.info("")
        logger.info(f"Task({self.task_type}): {self.name}")

        return self.impl.run()

class QSVMSession():
    def __init__(self, path, vmname, is_svc):

        # Check incoming arguments
        if not isinstance(path, str) or path == "":
            raise ValueError("Invalid path passed to QSVMSession")

        if not isinstance(vmname, str) or vmname == "":
            raise ValueError("Invalid vmname passed to QSVMSession")

        if not isinstance(is_svc, bool):
            raise ValueError("Invalid is_svc passed to QSVMSession")

        # Create the config directory, if it doesn't exist
        if not os.path.exists(path):
            os.makedirs(path)

        # Config paths
        qsvm_config_path = os.path.join(path, "qsvm.yaml")
        vm_config_dir = os.path.join(path, vmname)
        vm_config_path = os.path.join(path, vmname, "config.yaml")
        vm_config_vars_path = os.path.join(path, vmname, "config.vars.yaml")

        # Create a new custom Jinja2 environment
        self.environ = jinja2.Environment(undefined=jinja2.StrictUndefined, keep_trailing_newline=True)

        # Add custom jinja2 filters
        for filter_name in j2helper.j2filters:
            self.environ.filters[filter_name] = j2helper.j2filters[filter_name]

        # Add custom jinja2 globals
        for global_name in j2helper.j2globals:
            self.environ.globals[global_name] = j2helper.j2globals[global_name]

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

        # Extract qsvm configuration vars
        qsvm_vars = obslib.extract_property(qsvm_config, "vars", optional=True, default={})
        qsvm_vars = obslib.coerce_value(qsvm_vars, (dict, type(None)))
        if qsvm_vars is None:
            qsvm_vars = {}

        # Extract config file vars
        vm_vars = obslib.extract_property(vm_config, "vars", optional=True, default={})
        vm_vars = obslib.coerce_value(vm_vars, (dict, type(None)))
        if vm_vars is None:
            vm_vars = {}

        # Read the config.vars.yaml file, if it exists
        vm_config_vars = {}
        if os.path.isfile(vm_config_vars_path):
            # Load and parse the config vars file
            with open(vm_config_vars_path) as file:
                vm_config_vars = yaml.safe_load(file)

            # Make sure we have the correct type
            if not isinstance(vm_config_vars, dict):
                raise ValueError("Config vars file is not a top level dictionary")

        # Merge vars, with vm vars taking precedence
        config_vars = {}
        config_vars.update(qsvm_vars)
        config_vars.update(vm_vars)
        config_vars.update(vm_config_vars)

        # Add standard vars
        config_vars["qsvm"] = {
            "vmname": vmname,
            "config_dir": vm_config_dir,
            "config_path": vm_config_path,
            "pid": os.getpid(),
            "is_svc": is_svc
        }

        config_vars["env"] = os.environ.copy()

        # Resolve reference in config vars and create a session to allow var reference resolving
        config_vars = obslib.eval_vars(config_vars, environment=self.environ)
        session = obslib.Session(template_vars=config_vars, environment=self.environ)

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
            workingdir = session.resolve(workingdir, str)

        if workingdir is None or workingdir == "":
            workingdir = os.path.join(path, vmname)

        # Extract exec command
        exec_cmd = obslib.extract_property(vm_config, "exec")
        exec_cmd = session.resolve(exec_cmd, str)

        # Extract qemu monitor config
        qemu_mon_path = obslib.extract_property(vm_config, "qemu_mon_path", optional=True, default="qemu-mon")
        qemu_mon_path = session.resolve(qemu_mon_path, (str, type(None)))

        # Extract qemu monitor config
        qemu_guest_path = obslib.extract_property(vm_config, "qemu_guest_path", optional=True, default="qemu-guest")
        qemu_guest_path = session.resolve(qemu_guest_path, (str, type(None)))

        # Extract prestart command
        prestart = obslib.extract_property(vm_config, "prestart", optional=True, default=[])
        prestart = obslib.coerce_value(prestart, (list, type(None)))
        if prestart is None:
            prestart = []

        prestart = [ConfigTask(x, session) for x in prestart]

        # Make sure there are no other keys left
        if len(vm_config.keys()) > 0:
            raise ValueError(f"Unknown keys in VM configuration: {vm_config.keys()}")

        if len(qsvm_config.keys()) > 0:
            raise ValueError(f"Unknown keys in QSVM configuration: {qsvm_config.keys()}")

        # Change to the working directory
        if not os.path.exists(workingdir):
            os.makedirs(workingdir)

        os.chdir(workingdir)

        # Process command line
        exec_cmd = shlex.split(exec_cmd)

        if qemu_mon_path is not None and qemu_mon_path != "":
            exec_cmd = exec_cmd + [
                "-qmp",
                f"unix:{qemu_mon_path},server,wait=off"
            ]

        if qemu_guest_path is not None and qemu_guest_path != "":
            exec_cmd = exec_cmd + [
                "-chardev",
                f"socket,path={qemu_guest_path},server=on,wait=off,id=qga0",
                "-device",
                "virtio-serial",
                "-device",
                "virtserialport,chardev=qga0,name=org.qemu.guest_agent.0"
            ]

        # Properties for the config object
        self.config_vars = config_vars
        self.workingdir = workingdir
        self.exec_cmd = exec_cmd
        self.qemu_mon_path = qemu_mon_path
        self.qemu_guest_path = qemu_guest_path

        self.prestart = prestart

    def run_prestart(self):
        for task_def in self.prestart:
            if task_def.run() != 0:
                logger.error("Task in prestart failed")
                return 1

        return 0

def process_install(args):

    # Try to work out how to call ourselves
    cmd = util.get_selfcmd(args.cmd)
    if cmd is None:
        logger.error("Could not determine how to invoke qsvm - Perhaps supply '--cmd'")
        return 1

    logger.debug(f"Using cmd to invoke qsvm: {cmd}")

    target = "network.target"
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

    ExecStart={cmd} --is_svc direct-start-vm %i
    ExecStop={cmd} --is_svc direct-stop-vm %i $MAINPID

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
        unit_path = os.path.expanduser("~/.config/systemd/user")
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
        if util.run_systemctl(args.user, ["daemon-reload"]).returncode != 0:
            logger.error("Systemctl daemon-reload call failed")
            return 1
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
    vm_config = ubuntu_sample

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

def process_direct_stop_vm(args):

    # Read the VM configuration
    try:
        vm_session = QSVMSession(args.config, args.vm, args.is_svc)
    except Exception as e:
        logger.error(f"Failed to read VM configuration: {e}")
        return 1

    # Get a reference to the target process
    try:
        qemu_process = psutil.Process(args.pid)
    except psutil.NoSuchProcess:
        logger.error(f"Process {args.pid} does not exist")
        return 1

    # Open the qemu monitor socket and ask qemu to shut down the VM
    if vm_session.qemu_mon_path is not None and vm_session.qemu_mon_path != "":
        count = 0
        while count < 2:
            count = count + 1

            try:
                with socket.socket(family=socket.AF_UNIX, type=socket.SOCK_STREAM) as conn:
                    path = os.path.realpath(vm_session.qemu_mon_path)
                    logger.debug(f"Attempting shutdown using qemu monitor socket: {path}")

                    conn.connect(path)
                    conn.setblocking(False)
                    stream = conn.makefile("rw")

                    # Could do a better job of sending the requests and processing the responses, but
                    # there isn't much to do with the responses, so they are discarded and it's best effort
                    # to send the 'system_powerdown' command.

                    # Read the initial header
                    resp = stream.readlines()

                    # Negotiate qmp capabilities
                    stream.write("{\"execute\": \"qmp_capabilities\"}\n")
                    stream.flush()
                    resp = stream.readlines()

                    # Send shutdown request
                    stream.write("{\"execute\": \"system_powerdown\"}\n")
                    stream.flush()
                    resp = stream.readlines()

                # Now wait for the process to finish
                qemu_process.wait(timeout=30)

                if not psutil.pid_exists(args.pid):
                    return 0

            except psutil.TimeoutExpired as e:
                logger.debug(f"Timeout waiting for qemu process to finish. Attempt {count}")
            except Exception as e:
                logger.error(f"Failed to shutdown VM via qemu-mon: {e}")

    else:
        logger.info("No monitor path to send shutdown request to QEMU process")

    # Shutdown the process via INT
    logger.info(f"Sending SIGINT to process: {args.pid}")
    qemu_process.send_signal(signal.SIGINT)
    try:
        qemu_process.wait(timeout=15)

        if not psutil.pid_exists(args.pid):
            return 0
    except psutil.TimeoutExpired as e:
        pass

    # Shutdown the process via KILL
    logger.info(f"Sending SIGKILL to process: {args.pid}")
    qemu_process.send_signal(signal.SIGKILL)
    try:
        qemu_process.wait(timeout=15)

        if not psutil.pid_exists(args.pid):
            return 0
    except psutil.TimeoutExpired as e:
        pass

    # Process didn't stop from monitor, INT or KILL...
    logger.error(f"Process still exists after SIGKILL")
    return 1

def process_test(args):
    print("ok")

def process_direct_start_vm(args):

    # Read the VM configuration
    vm_session = QSVMSession(args.config, args.vm, args.is_svc)

    # Run prestart tasks
    if vm_session.run_prestart() != 0:
        return 1

    # Start the VM
    logger.info(f"VM exec: {' '.join(vm_session.exec_cmd)}")
    sys.stdout.flush()
    os.execvp(vm_session.exec_cmd[0], vm_session.exec_cmd)

    # If we're here, then we failed to load the qemu process
    logger.error("execvp returned/failed to start qemu process")
    return 1

def process_start(args):
    return util.run_systemctl(args.user, ["start", f"{args.svc}@{args.vm}"]).returncode

def process_stop(args):
    return util.run_systemctl(args.user, ["stop", f"{args.svc}@{args.vm}"]).returncode

def should_restart(args):

    # Check if we're doing a conditional restart
    if not args.if_changed:
        # Restart should be performed
        return True

    # Check the command line for the current qemu process against the configuration
    # and restart if they are different

    # This implicitly works against systemd, so we'll set is_svc, whether it's been specified by the user or not
    # The 'is_svc' argument can influence the vm_session exec command line, so we need to set it to make sure
    # we get the same exec cmd as would have been determined through systemd
    args.is_svc = True

    # Read the VM configuration
    try:
        vm_session = QSVMSession(args.config, args.vm, args.is_svc)
    except Exception as e:
        raise exception.QSVMException(f"Failed to read VM configuration: {e}")

    # Retrieve the current PID from systemd
    ret = util.run_systemctl(args.user, ["show", f"{args.svc}@{args.vm}", "--property=MainPID"], capture=True)
    lines = ret.stdout.decode("utf-8").split("\n")
    if len(lines) < 1:
        raise exception.QSVMException("Unexpected result from systemctl show. Expected output")

    # Process the output from show
    items = lines[0].split("=")
    if len(items) != 2 or items[0] != "MainPID":
        raise exception.QSVMException(f"Unexpected result from systemctl show. Expecting 'MainPID=??'. Got {lines[0]}")

    # Convert pid str to int
    try:
        pid = int(items[1])
    except ValueError as e:
        raise exception.QSVMException(f"Pid from systemctl is not valid. Expected int. Received {items[1]}")

    # Check for 0 pid - nothing is currently running
    if pid == 0:
        logger.debug(f"Found no current PID for qemu service")
        return True

    # Get a reference to the pid
    try:
        logger.debug(f"Found running qemu process with pid {pid}")
        qemu_process = psutil.Process(pid)
    except psutil.NoSuchProcess:
        raise exception.QSVMException(f"Process referenced by systemctl doesn't exist: {pid}")

    # Compare the exec cmds of the running process and what we read from the configuration
    running_cmd = ' '.join(qemu_process.cmdline()).strip()
    config_cmd = ' '.join(vm_session.exec_cmd).strip()
    logger.debug(f"Running cmdline: {running_cmd}")
    logger.debug(f"Config cmdline: {config_cmd}")

    if running_cmd != config_cmd:
        logger.info("Running cmdline is different than configured cmdline")
        return True

    # List of files to check for modification times newer than the running VM process
    file_list = [
        os.path.join(args.config, args.vm, "config.yaml"),
        os.path.join(args.config, args.vm, "config.vars.yaml")
    ]

    process_created = qemu_process.create_time()

    # Check files and trigger restart if any are newer than the process time
    for file_path in file_list:
        if os.path.exists(file_path) and os.path.getmtime(file_path) > process_created:
            logger.info(f"File ({file_path}) is newer than the qemu process create time")
            return True

    logger.info("Running and configured cmdlines are identical and files are older than the process. Not restarting")
    return False

def process_restart(args):
    # Restart the process, if should_restart determined so and check systemctl result
    if should_restart(args) and util.run_systemctl(args.user, ["restart", f"{args.svc}@{args.vm}"]).returncode != 0:
        logger.error("Systemd restart for service returned non-zero")
        return 1

def process_enable(args):
    return util.run_systemctl(args.user, ["enable", f"{args.svc}@{args.vm}"]).returncode

def process_disable(args):
    return util.run_systemctl(args.user, ["disable", f"{args.svc}@{args.vm}"]).returncode


