from pwnlib.tubes.remote import remote

from docker.errors import NotFound
from docker.models.containers import Container
import functools
import time
import os
from pwnlib.elf.elf import ELF

from knecht.docker_debug import utils, docker_utils, tools
from knecht.docker_debug.proxy import proxy
from knecht.docker_debug.utils import client, log

class docker(remote):
    def __init__(self, host: str, port: int, container_id: str = None, exe: str | ELF = None, ssl: bool = False, *args, **kwargs):
        self.container:Container = None
        self.proxy:proxy = None
        self.exe = exe
        self.container_key = utils.compute_container_key()

        log.info(f"Initializing container with ID: {container_id}")
        self.initialize_container(container_id, port)

        self.exe = exe or self.find_executable()
        log.info(f"Executable set to: {self.exe}")

        self.check_and_download_tools()
        self.check_and_upload_gdbserver()

        super().__init__(*args, host=host, port=port, ssl=ssl, **kwargs)

        pid = self.ensure_exe_running()
        self.start_exec_proxy(['gdbserver', '--once', '--attach', 'stdio', str(pid)], environment=self.get_environment(), stdin=True, privileged=True, socket=True)

    def initialize_container(self, container_id: str, port: int):
        """Build/start the image/container if necessary."""
        if container_id:
            try:
                self.container = client.containers.get(container_id)
                log.info(f"Container {container_id} found.")
            except NotFound:
                log.warning(f"Container {container_id} not found.")

        if not self.container:
            log.info("Building and running a new container.")
            self.image = docker_utils.check_build_if_necessary(
                labels={'build_container_key' : self.container_key, 
                        'file_hash' : utils.compute_file_hash('Dockerfile')},
                tag=f'pwn-{self.container_key}',
                path='.'
            )
            self.container = docker_utils.check_run_if_necessary(
                labels={f'run_container_key': self.container_key},
                image=self.image,
                detach=True,
                ports={f'{port}/tcp': port}
            )
            log.info(f"New container started with image: {self.image}")

    def check_and_download_tools(self):
        tools_path = os.path.join(utils.module_dir, 'tools')
        if not os.path.exists(tools_path):
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
        for _ in range(30):
            output = self.container.exec_run(
                ['pidof', self.exe.path if isinstance(self.exe, ELF) else self.exe],
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
        pids = self.get_process_ids()
        if not pids:
            log.error('The exe has not been found inside the container')
            raise NotFound('The exe has not been found inside the container')
        return int(pids[0])

    @functools.wraps(Container.exec_run)
    def start_exec_proxy(self, *args, **kwargs) -> tuple[str, int]:
        """Start the given exec and forward stdio to a socket listening at a free port."""
        log.info("Starting exec proxy.")
        sock = self.container.exec_run(*args, **kwargs).output._sock
        self.proxy = proxy(sock)
        return self.proxy.remote
    
    def close(self):
        self.proxy.close()