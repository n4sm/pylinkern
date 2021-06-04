#!/bin/sh

mkdir -p mountpoint

qemu-system-x86_64 -S -s \
    -kernel ./bzImage \
    -initrd ./initramfs.cpio.gz \
    -append 'console=ttyS0 loglevel=3 oops=panic panic=1 nokaslr nosmap' \
    -fsdev local,id=exp1,path=./mountpoint,security_model=mapped \
    -device virtio-9p-pci,fsdev=exp1,mount_tag=mountpoint \
    -no-reboot \
    -nographic
