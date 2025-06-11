import os

from setuptools import find_packages, setup

with open("README.md") as readme_file:
    README = readme_file.read()

setup_args = {
    "name": "qsvm",
    "version": os.environ["BUILD_VERSION"],
    "description": "QEMU Systemd virtual machine management tool",
    "long_description_content_type": "text/markdown",
    "long_description": README,
    "license": "MIT",
    "packages": find_packages(where="src", include=["qsvm", "qsvm.*"]),
    "author": "Jesse Reichman",
    "keywords": ["QEMU", "Systemd", "VM", "Virtual Machine"],
    "url": "https://github.com/archmachina/qsvm",
    "download_url": "https://pypi.org/project/qsvm/",
    "entry_points": {"console_scripts": ["qsvm = qsvm.cli:main"]},
    "package_dir": {"": "src"},
    "install_requires": ["obslib>=0.2.0,<0.3.0", "psutil>=6.1.1"],
}

if __name__ == "__main__":
    setup(**setup_args, include_package_data=True)
