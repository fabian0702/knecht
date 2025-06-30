# knecht
A extension and collection of usefull features / scripts for binary exploitation

## Installation

### Using Poetry
```bash
poetry add git+https://github.com/fabian0702/knecht.git
``` 
### Using pip:
```bash
pip install git+https://github.com/fabian0702/knecht.git
``` 

## Docker
This allows the binary to be ran directly in the container directly from the comfort of your normal solvescript

### Example:
```py
from pwn import *
from knecht import *

d = docker('localhost', 1337)   # connect to the socat of the container on localhost:1337

gdb.attach(d)   # open a gdb debugger window

d.interactive()  # normal pwntools behaviour
```

### Arguments:
**host**: the host which the container listens on, usually just localhost   
**port**: the port the binary listens on   
**container_id**: (optional) the id / name of a existing container to attach too instead of creating a new one   
**use_nsenter**: if enabled knecht uses nsenter inside the container to enter the namespace of the process allowing debuging in additional sandboxing like nsjail   
**pid**: attach directly to target pid, useful if there is some init logic but you still want the debug capabilities   
**docker_run_kwargs**: this enables passing additionals args to docker run when knecht starts a new container (like privileged for nsjail)   
**ssl/exe/...**: (optional) the normal arguments for a pwntools remote / process object   


## Qiling
This allows to debug cross-arch binarys or binarys with anoying anti-debug
### Example:
```py
from pwn import *
from knecht import *

q = qiling(['/<executable'])   # setup the emulator

def script(q:qiling):

    gdb.attach(q)   # open a gdb debugger window

    q.interactive()  # normal pwntools behaviour

q.run(script)
```

### Args
**argv**: Arguments to the process, argv[0] being the process name/path, eiter a path to inside the rootfs or the absolute path in the rootfs (the binary is taken from the cwd by its basename)   
**rootfs**: (optional) A path to the rootfs for the emulator, can be ommited as, it will be extracted from a docker container if a Dockerfile is present   
**env**: (optional) The env of the process, if omited the env of the current shell is used   
**docker_image**: (optional) A id / name of a docker image, which will be used to extract the rootfs if it's missing, if omited the Dockerfile in the cwd is used   
**verbose/...**: (optional) Additional arguments to the underlying Qiling instance   

