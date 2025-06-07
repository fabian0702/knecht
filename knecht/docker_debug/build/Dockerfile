FROM ubuntu:24.04

RUN apt update && apt install -y \
    autopoint \
    binutils-multiarch \
    bison \
    file \
    flex \
    g++ \
    g++-aarch64-linux-gnu \
    g++-arm-linux-gnueabi \
    g++-mips-linux-gnu \
    g++-mipsel-linux-gnu \
    g++-powerpc-linux-gnu \
    gcc \
    gcc-aarch64-linux-gnu \
    gcc-arm-linux-gnueabi \
    gcc-mips-linux-gnu \
    gcc-mipsel-linux-gnu \
    gcc-powerpc-linux-gnu \
    git \
    libtool \
    m4  \
    make \
    patch \
    pkg-config \
    python3.12 \
    python3-aiohttp \
    libpython3-dev \
    texinfo \
    wget \
    xz-utils

ARG arch=x86_64

WORKDIR /app/gdb

RUN git clone https://github.com/guyush1/gdb-static.git /app/gdb/

COPY download_script.patch /app/gdb/

RUN python3.12 -u /app/gdb/src/docker_utils/download_musl_toolchains.py ${arch}

COPY ./Makefile /app/gdb/

WORKDIR /app/gdb/

RUN sed -i 's|git@github.com:|https://github.com/|g' .gitmodules && \
    sed -i 's|\.git$|.git|g' .gitmodules

RUN git submodule update --init --recursive

RUN make download-packages

WORKDIR /app/gdb/src/submodule_packages/binutils-gdb/

COPY gdb_binutils.patch /app/gdb/

RUN git apply /app/gdb/gdb_binutils.patch

WORKDIR /app/gdb/

ENV TERM=xterm-256color

RUN bash -i -c "/entrypoint.sh make -j$(nproc) build-${arch}-slim"

CMD ["bash", "-c", "cp /app/gdb/build/artifacts/x86_64_slim/gdbserver /tools/gdbserver && chown $UID:$UID /tools/gdbserver"]