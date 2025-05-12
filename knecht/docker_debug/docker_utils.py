import os
import sys

from tarfile import TarFile
from io import BytesIO

import docker
from docker.models.containers import Container
from docker.models.images import Image
from docker.errors import BuildError

from knecht.docker_debug.utils import client


def upload_directory(container:Container, src_path:str, dest_path:str):
    """upload a directiory/file from src_path to dest_path in the container"""

    tools_tar = BytesIO()
    with TarFile(mode='w', fileobj=tools_tar) as tar:
        tar.add(src_path, dest_path)

    tools_tar.seek(0)

    container.put_archive(f'/', tools_tar)

def check_build_if_necessary(labels:dict[str,str]={}, *args, **kwargs) -> Image:
    """check if there already is a image with the labels else build it with the provided args"""
    images = client.images.list(filters={'label':label_dict_to_list(labels)})
    if images:
        return images[0]
    else:
        return build_image(*args, labels=labels, **kwargs)

def label_dict_to_list(labels:dict[str, str]) -> list[str]:
    return [f'{k}={v}' for k, v in labels.items()]
    
def check_run_if_necessary(labels:dict[str,str]={}, *args, **kwargs ) -> Container:
    """check if there already is a running container with the labels else run one with the provided args"""

    containers = client.containers.list(filters={'label':label_dict_to_list(labels), 'status':'running'}, limit=1)
    if containers:
        return containers[0]
    else:
        return client.containers.run(*args, labels=labels, **kwargs)


def build_image(*args, **kwargs) -> Image | None:
    """a wrapper around client.api.build which provides formated console output of the build process"""

    client = docker.from_env()

    kwargs.update({'decode':True, 'pull':True})

    response_stream:list[dict[str, str]] = client.api.build(*args, **kwargs)

    status_dict = {}

    for chunk in response_stream:
        type, *other_info = chunk.keys()
        match type:
            case 'error':
                raise BuildError(chunk['error'], response_stream)
            case 'errorDetail':
                raise BuildError(chunk['errorDetail']['message'], response_stream)
            case 'stream':
                sys.stdout.write(chunk['stream'])
            case 'status':
                if 'id' in other_info:
                    change_id = chunk['id']
                    if not change_id in status_dict:
                        sys.stdout.write('\n')
                    status_dict.update({change_id:{'id':change_id, 'status':chunk['status'], 'progress':chunk.get('progress', '')}})
                    for _ in status_dict.keys():
                        sys.stdout.write('\033[F\033[K')
                    for update in status_dict.values():
                        sys.stdout.write(f"{update['id']}: {update['status']} {update.get('progress', '')}\n")
                else:
                    sys.stdout.write(chunk['status'])
            case 'aux':
                value = chunk['aux']
                if 'ID' in value:
                    image_id = value['ID'].split(':')[-1]
                else:
                    sys.stdout.write(f'{chunk}')
            case _:
                sys.stdout.write(f'{chunk}')

    if not image_id:
        raise BuildError('no image_id found after building image')
        
    return client.images.get(image_id)