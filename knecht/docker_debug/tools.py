import os
import tarfile
import shutil
import requests
import io

from knecht.docker_debug.docker_utils import build_image
from knecht.docker_debug.utils import client, log


GDB_URL = "https://github.com/guyush1/gdb-static/releases/download/v16.3-static/gdb-static-full-x86_64.tar.gz"
PIDOF_URL = "https://busybox.net/downloads/binaries/1.35.0-x86_64-linux-musl/busybox_PIDOF"

MODULE_DIRECTORY = os.path.dirname(__file__)
TOOLS_DIRECTORY = os.path.join(MODULE_DIRECTORY, 'tools')

def create_tools_directory():
    """Create a clean tools directory."""
    os.makedirs(TOOLS_DIRECTORY, exist_ok=True)
    shutil.rmtree(TOOLS_DIRECTORY, ignore_errors=True)
    os.makedirs(TOOLS_DIRECTORY, exist_ok=True)

def download_file(url):
    """Download a file from a URL and return the content."""
    response = requests.get(url)
    response.raise_for_status()
    return response.content

def extract_tarball(content, extract_path):
    """Extract a tarball from content to the specified path."""
    with io.BytesIO(content) as tar_bytes:
        with tarfile.open(fileobj=tar_bytes, mode='r:gz') as tar:
            tar.extractall(path=extract_path)

def save_binary(content, filename):
    """Save binary content to a file in the tools directory."""
    file_path = os.path.join(TOOLS_DIRECTORY, filename)
    with open(file_path, 'wb') as f:
        f.write(content)
    return file_path

def make_executable(path):
    """Make a file or all files in a directory executable."""
    if os.path.isdir(path):
        for file in os.listdir(path):
            file_path = os.path.join(path, file)
            if os.path.isfile(file_path):
                os.chmod(file_path, 0o755)
    else:
        os.chmod(path, 0o755)

def setup_tools():
    """Download and set up debugging tools."""
    create_tools_directory()
    
    builder_image = build_image(tag='tool_builder', path=os.path.join(MODULE_DIRECTORY, 'build'))
    if not builder_image:
        log.error("Failed to build the image for downloading tools.")
        return
    client.containers.run(builder_image, remove=True, volumes={TOOLS_DIRECTORY: {'bind': '/tools', 'mode': 'rw'}}, environment={'UID':str(os.getuid())})
    
    # Download and save pidof
    pidof_content = download_file(PIDOF_URL)
    save_binary(pidof_content, 'pidof')
    
    # Make all tools executable
    make_executable(TOOLS_DIRECTORY)