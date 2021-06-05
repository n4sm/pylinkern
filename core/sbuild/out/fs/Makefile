TARGET = ../initramfs.cpio.gz

unpack:
	zcat $(TARGET) | cpio -idmv

new:
	find . | cpio -o -H newc | gzip > $(TARGET)
