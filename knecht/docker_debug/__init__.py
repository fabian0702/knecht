from pwnlib.tubes.remote import remote

from docker.errors import NotFound
from docker.models.containers import Container
import functools
import time
import os
from pwnlib.elf.elf import ELF
from typing import Optional

from knecht.docker_debug import utils, docker_utils, tools
from knecht.docker_debug.proxy import proxy
from knecht.docker_debug.utils import client, log

class docker(remote):
    def __init__(self, host: str, port: int, target:Optional[int | str | ELF] = None, use_nsenter:bool = False, gdb_server_port:Optional[int]=None, container: Optional[str] = None, ssl: bool = False, docker_run_kwargs:Optional[dict]=None, *args, **kwargs):
        self.proxy:Optional[proxy] = None
        self.exe = None
        self.gdb_server_port = gdb_server_port
        self.docker_run_args = docker_run_kwargs
        self.use_nsenter = use_nsenter
        self.pid = None
        self.container_key = utils.compute_container_key()

        self.container = self.initialize_container(container, port)
        log.info(f"Initializing container with ID: {self.container.name}")

        self.check_and_download_tools()
        self.check_and_upload_gdbserver()

        if not self.check_gdbserver():
            log.error("gdbserver not found in the container. Upload failed.")

        if isinstance(target, int):
            self.pid = target
        elif isinstance(target, ELF):
            self.exe = target.path
        elif isinstance(target, str):
            self.exe = target

        self.exe:Optional[str] = self.exe or self.find_executable()
        
        log.info(f"Executable set to: {self.exe}")

        super().__init__(*args, host=host, port=port, ssl=ssl, **kwargs)

        if not self.gdb_server_port:
            self.pid = self.pid or self.ensure_exe_running()

    def initialize_container(self, container_id: Optional[str], port: int):
        """Build/start the image/container if necessary."""
        if container_id:
            try:
                container = client.containers.get(container_id)
                log.info(f"Container {container_id} found.")
                return container
            except NotFound:
                log.warning(f"Container {container_id} not found.")

        log.info("Building and running a new container.")
        self.image = docker_utils.check_build_if_necessary(
            labels={'build_container_key' : self.container_key, 
                    'file_hash' : utils.compute_file_hash('Dockerfile')},
            tag=f'pwn-{self.container_key}',
            path='.'
        )
        container = docker_utils.check_run_if_necessary(
            labels={f'run_container_key': self.container_key},
            image=self.image,
            detach=True,
            ports={f'{port}/tcp': port},
            extra_args=self.docker_run_args
        )
        log.info(f"New container started with image: {self.image}")

        return container

    def check_and_download_tools(self):
        tools_path = os.path.join(utils.module_dir, 'tools')
        if not os.path.exists(os.path.join(tools_path, 'gdbserver')):
            tools.setup_tools()

    def find_executable(self) -> str:
        """Find the name of the executable by looking at the files and the container's entrypoint/cmd."""
        exe = utils.find_exe(self.container)
        log.info(f"Executable found: {exe}")
        return exe

    def env_list_to_dict(self, env_list: list[str]) -> dict[str, str]:
        """Convert from ['KEY=VALUE'] to {'KEY': 'VALUE'}."""
        return {key: value for key, value in (item.split('=', 1) for item in env_list)}

    def get_environment(self) -> dict[str, str]:
        """Retrieve the environment with modified PATH variable."""
        env_list = self.container.attrs['Config']['Env']
        log.debug(f"Environment list: {env_list}")
        env = self.env_list_to_dict(env_list)
        env['PATH'] = f'/tools-{self.container_key}/:{env.get("PATH", "")}'
        return env

    def check_gdbserver(self) -> bool:
        """Check if gdbserver is already in the container from a previous run."""
        result = self.container.exec_run(['gdbserver'], environment=self.get_environment())
        is_present = result.exit_code != 127
        log.info(f"gdbserver {'found' if is_present else 'not found'} in container.")
        return is_present

    def check_and_upload_gdbserver(self) -> None:
        """Check if gdbserver is already in the container. If not, upload it to `/tools-{container_key}/`."""
        if not self.check_gdbserver():
            log.info("gdbserver not found. Uploading gdbserver to container.")
            src_path = os.path.join(utils.module_dir, 'tools')
            docker_utils.upload_directory(self.container, src_path, f'/tools-{self.container_key}/')

    def get_process_ids(self) -> list[str]:
        """Retrieve process IDs of the executable running inside the container."""
        if not self.exe:
            raise Exception('No pid / exe found / provided, please invoke with exe=<binary name>')
        for _ in range(30):
            output = self.container.exec_run(
                ['pidof', os.path.basename(self.exe.path if isinstance(self.exe, ELF) else self.exe)],
                environment=self.get_environment()
            ).output.decode().strip()
            pids = output.split()
            if pids:
                log.info(f"Process IDs found: {pids}")
                return pids
            time.sleep(0.05)
        log.warning("No process IDs found.")
        return []

    def ensure_exe_running(self) -> int:
        """Ensure the executable is running inside the container."""
        for _ in range(30):
            pids = self.get_process_ids()
            if pids:
                log.info(f"Executable is running with PID: {pids[0]}")
                return int(pids[0])
            log.info("Executable not found, waiting...")
            time.sleep(0.05)
        log.error("Executable not found after multiple attempts.")

    def attach_gdbserver(self):
        """Attach a gdbserver to the running executable."""
        cmd = ['gdbserver', '--once', '--attach', 'stdio', str(self.pid)]
        if self.gdb_server_port:
            cmd = ["nc", "localhost", str(self.gdb_server_port)]
        if self.use_nsenter:
            cmd = ['nsenter', '-a', '-t', str(self.pid)] + cmd

        log.info("Starting exec proxy.")
        sock = self.container.exec_run(cmd=cmd, environment=self.get_environment(), stdin=True, privileged=True, socket=True).output._sock
        
        self.proxy = proxy(sock)
        return self.proxy.remote
    
    def close(self):
        if self.proxy:
            log.info("Closing proxy connection.")
            self.proxy.close()
