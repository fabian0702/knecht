mkdir -p tools
rm -f tools/*
wget -P tools https://github.com/guyush1/gdb-static/releases/download/v16.3-static/gdb-static-full-x86_64.tar.gz
tar -xvzf tools/gdb-static-full-x86_64.tar.gz -C tools

wget -P tools https://busybox.net/downloads/binaries/1.35.0-x86_64-linux-musl/busybox_PIDOF
chmod +x tools/*
mv tools/busybox_PIDOF tools/pidof