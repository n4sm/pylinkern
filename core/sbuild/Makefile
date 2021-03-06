# https://github.com/t00sh/vm-make/blob/master/linux/Makefile

export CONF_LINUX_BUILD=$(PWD)
export CONF_LINUX_BZIMAGE=$(CONF_LINUX_BUILD)/out/bzImage
export CONF_LINUX_SYSTEMMAP=$(CONF_LINUX_BUILD)/out/System.map

export CONF_LINUX_ARCH=x86
# edit these two fields to target another kernel
export CONF_LINUX_ARCHIVE=linux-5.9.3.tar.gz
export CONF_LINUX_URL=https://cdn.kernel.org/pub/linux/kernel/v5.x/$(CONF_LINUX_ARCHIVE)
export CONF_CPUS=4

# General setup
BUILD=$(CONF_LINUX_BUILD)/build
SRC=$(CONF_LINUX_BUILD)/src
CONFIG=$(CONF_LINUX_BUILD)/config
BZIMAGE=$(CONF_LINUX_BZIMAGE)
SYSTEM_MAP=$(CONF_LINUX_SYSTEMMAP)
VMLINUX = $(CONF_LINUX_BUILD)/out/vmlinux
ARCHIVE=$(CONF_LINUX_BUILD)/$(CONF_LINUX_ARCHIVE)
SRC_DONE=$(SRC)/.done

base: $(SRC_DONE)

	mkdir -p $(BUILD);
	make -C $(SRC) O=$(BUILD) defconfig;
	cp build/.config defconfig
	cat kconfiglib.patch >> $(SRC)/scripts/kconfig/Makefile

	cp ../obuild.py Kconfiglib/examples
	make -C build/ ARCH=x86_64 scriptconfig SCRIPT=../Kconfiglib/examples/obuild.py;
	cp $(CONFIG) $(BUILD)/.config;
	make -C $(BUILD) olddefconfig;
	make -C $(BUILD) -j$(CONF_CPUS);
	
	cp $(BUILD)/System.map $(SYSTEM_MAP);
	cp $(BUILD)/arch/$(CONF_LINUX_ARCH)/boot/bzImage $(CONF_LINUX_BZIMAGE);
	cp $(BUILD)/vmlinux $(VMLINUX)

retry:
	if test -z "$(BUILD)"; then \
		echo "exit, bad structure";\
		exit -1; \
	fi

	cp ../obuild.py Kconfiglib/examples	
	make -C build/ ARCH=x86_64 scriptconfig SCRIPT=../Kconfiglib/examples/obuild.py
	cp $(CONFIG) $(BUILD)/.config
	make -C $(BUILD) olddefconfig
	make -C $(BUILD) -j$(CONF_CPUS)

	cp $(BUILD)/System.map $(SYSTEM_MAP)
	cp $(BUILD)/arch/$(CONF_LINUX_ARCH)/boot/bzImage $(CONF_LINUX_BZIMAGE)
	cp $(BUILD)/vmlinux $(VMLINUX)

internal:
	if test -z "$(BUILD)"; then \
		echo "exit, bad structure";\
		exit -1; \
	fi

	cp ../obuild.py Kconfiglib/examples
	make -C build/ ARCH=x86_64 scriptconfig SCRIPT=../Kconfiglib/examples/obuild.py SCRIPT_ARG=GDB_INTERNAL
	cp $(CONFIG) $(BUILD)/.config
	make -C $(BUILD) olddefconfig
	make -C $(BUILD) -j$(CONF_CPUS)

install:
	git clone https://github.com/n4sm/Kconfiglib
	cp ../obuild.py Kconfiglib/examples

$(SRC_DONE): $(ARCHIVE)
	mkdir -p $(SRC)
	tar --strip 1 -xvf $(ARCHIVE) -C $(SRC)/

$(ARCHIVE):
	if test -z "$(CONF_LINUX_URL)"; then \
	  cp $(CONF_LINUX_ARCHIVE) .; \
	else \
	  wget $(CONF_LINUX_URL) -O $(ARCHIVE); \
	fi;

clean:
	rm -rf out/*
	rm config.old
