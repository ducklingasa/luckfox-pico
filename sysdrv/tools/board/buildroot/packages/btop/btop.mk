################################################################################
#
# btop
#
################################################################################

BTOP_VERSION = 1.4.8
BTOP_SOURCE = btop-armv7-unknown-linux-musleabi.tar.gz
BTOP_SITE = https://github.com/aristocratos/btop/releases/download/v$(BTOP_VERSION)
BTOP_LICENSE = Apache-2.0
BTOP_LICENSE_FILES = btop/LICENSE

define BTOP_INSTALL_TARGET_CMDS
	$(INSTALL) -D -m 0755 $(@D)/btop/bin/btop $(TARGET_DIR)/usr/bin/btop
	$(INSTALL) -d $(TARGET_DIR)/usr/share/btop/themes
	cp -a $(@D)/btop/themes/. $(TARGET_DIR)/usr/share/btop/themes/
endef

$(eval $(generic-package))
