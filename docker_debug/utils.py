import os

from hashlib import sha256

import docker
from docker.models.containers import Container

from pwnlib.log import getLogger


log = getLogger(__name__)

client = docker.from_env()

module_dir = os.path.dirname(__file__)

def compute_container_key():
    return sha256(os.path.dirname(os.getcwd()).encode()).hexdigest()[:12]

def get_entrypoint_components(container:Container):
    return ' '.join([container.attrs['Path']] + container.attrs["Args"])

def find_exe(container:Container) -> str:
    entrypoint_components = get_entrypoint_components(container)
    for file in os.listdir(os.getcwd()):
        if file in entrypoint_components:
            return file
            
    raise Exception("no process found")