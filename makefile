# === Project Configuration ===
KERNEL_MODULE = mfw_kmod
CLI_BINARY = mfw
KDIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)
BUILD_DIR = build
DIST_DIR = dist
PKG_NAME = minifw_pkg
ARCH := amd64

all: $(BUILD_DIR)/$(KERNEL_MODULE).ko $(BUILD_DIR)/$(CLI_BINARY)

$(BUILD_DIR)/$(KERNEL_MODULE).ko:
	@mkdir -p $(BUILD_DIR)
	$(MAKE) -C $(KDIR) M=$(PWD)/kernel modules
	@cp kernel/$(KERNEL_MODULE).ko $(BUILD_DIR)/

$(BUILD_DIR)/$(CLI_BINARY): user/main.cpp user/mfw.h
	@mkdir -p $(BUILD_DIR)
	g++ -o $(BUILD_DIR)/$(CLI_BINARY) user/main.cpp

clean:
	$(MAKE) -C $(KDIR) M=$(PWD)/kernel clean
	rm -rf $(BUILD_DIR) $(DIST_DIR) $(PKG_NAME)

deb: all
	@echo "Packaging into .deb..."
	@mkdir -p $(PKG_NAME)/DEBIAN
	@mkdir -p $(PKG_NAME)/usr/bin
	@mkdir -p $(PKG_NAME)/lib/modules/$(shell uname -r)/extra

	cp $(BUILD_DIR)/$(CLI_BINARY) $(PKG_NAME)/usr/bin/
	cp $(BUILD_DIR)/$(KERNEL_MODULE).ko $(PKG_NAME)/lib/modules/$(shell uname -r)/extra/

	cp debian/control $(PKG_NAME)/DEBIAN/control
	cp debian/postinst $(PKG_NAME)/DEBIAN/postinst
	cp debian/prerm $(PKG_NAME)/DEBIAN/prerm
	chmod +x $(PKG_NAME)/DEBIAN/postinst $(PKG_NAME)/DEBIAN/prerm

	@mkdir -p $(DIST_DIR)
	dpkg-deb --build $(PKG_NAME) $(DIST_DIR)/minifirewall_1.0_$(ARCH).deb
	@echo "Debian package created at: $(DIST_DIR)/minifirewall_1.0_$(ARCH).deb"

.PHONY: all clean deb
