################################################################################
#
# vpn-web
#
################################################################################

VPN_WEB_VERSION = 1
VPN_WEB_SITE = $(TOPDIR)/package/vpn-web/src
VPN_WEB_SITE_METHOD = local
VPN_WEB_DEPENDENCIES = json-c

define VPN_WEB_BUILD_CMDS
	$(TARGET_MAKE_ENV) $(MAKE) -B -C $(@D) CC="$(TARGET_CC)" \
		CPPFLAGS="$(TARGET_CPPFLAGS)" CFLAGS="$(TARGET_CFLAGS)" \
		LDFLAGS="$(TARGET_LDFLAGS)"
endef

define VPN_WEB_INSTALL_TARGET_CMDS
	$(INSTALL) -D -m 0755 $(@D)/vpn-native $(TARGET_DIR)/opt/vpn-web/vpn-native
endef

$(eval $(generic-package))
