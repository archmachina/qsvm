import hashlib
import json
import logging
import shlex
import sys
import subprocess

import qsvm.exception as exception

logger = logging.getLogger(__name__)

def get_selfcmd(override=None):
    # Use supplied override, if provided
    if override is not None and override != "":
        return override

    # Try sys.argv[0]
    cmd = f"\"{sys.executable}\" \"{sys.argv[0]}\""
    ret = subprocess.run(f"{cmd} test", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if ret.returncode == 0:
        return cmd

    # Try __file__
    cmd = f"\"{sys.executable}\" \"{__file__}\""
    ret = subprocess.run(f"{cmd} test", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if ret.returncode == 0:
        return cmd

    return None

def run_systemctl(user, args, *, capture=False, check=False):

    cmd = ["systemctl"]
    if user:
        cmd.append("--user")

    cmd = cmd + args

    logger.debug(f"Calling systemctl: {shlex.join(cmd)}")
    sys.stdout.flush()
    ret = subprocess.run(cmd, capture_output=capture)

    if ret.returncode != 0:
        logger.error(f"Systemctl returned non-zero: {ret.returncode}")

        # Raise error, if requested
        if check:
            raise exception.QSVMSystemctlException(f"Systemctl returned non-zero: {ret.returncode}")

    return ret

def generate_hash(source, hash_len):

    # Check arguments
    if source is None:
        raise exception.QSVMTemplateException("Source supplied to generate_hash is None")

    if not isinstance(hash_len, int):
        raise exception.QSVMTemplateException("Invalid hash len supplied to generate_hash")

    # Generate the hash from the source
    instance = hashlib.shake_256()
    instance.update(str(source).encode("utf-8"))
    res = instance.hexdigest(hash_len)

    return res

