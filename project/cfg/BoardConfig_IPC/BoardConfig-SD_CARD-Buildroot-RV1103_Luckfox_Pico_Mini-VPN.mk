#!/bin/bash

#################################################
# 	Board Config
#################################################
# Luckfox Pico Mini A as WireGuard VPN server (see VPN_SERVER_PLAN.md)
export LF_ORIGIN_BOARD_CONFIG=BoardConfig-SD_CARD-Buildroot-RV1103_Luckfox_Pico_Mini-VPN.mk
# Target CHIP
export RK_CHIP=rv1106

# app config: no camera application on the VPN server
# export RK_APP_TYPE=RKIPC_RV1103

# Config CMA size in environment (was 24M; fall back to 4M if a driver complains)
export RK_BOOTARGS_CMA_SIZE="1M"

# Kernel dts
export RK_KERNEL_DTS=rv1103g-luckfox-pico-mini-vpn.dts

#################################################
#	BOOT_MEDIUM
#################################################

# Target boot medium
export RK_BOOT_MEDIUM=sd_card

# Uboot defconfig fragment
export RK_UBOOT_DEFCONFIG_FRAGMENT=rk-emmc.config

# config partition in environment
# RK_PARTITION_CMD_IN_ENV format:
#     <partdef>[,<partdef>]
#       <partdef> := <size>[@<offset>](part-name)
# Note:
#   If the first partition offset is not 0x0, it must be added. Otherwise, it needn't adding.
export RK_PARTITION_CMD_IN_ENV="32K(env),512K@32K(idblock),256K(uboot),32M(boot),256M(userdata),6G(rootfs)"

# config partition's filesystem type (squashfs is readonly)
# emmc:    squashfs/ext4
# nand:    squashfs/ubifs
# spi nor: squashfs/jffs2
# RK_PARTITION_FS_TYPE_CFG format:
#     AAAA:/BBBB/CCCC@ext4
#         AAAA ----------> partition name
#         /BBBB/CCCC ----> partition mount point
#         ext4 ----------> partition filesystem type
export RK_PARTITION_FS_TYPE_CFG=rootfs@IGNORE@ext4,userdata@/userdata@ext4

#################################################
#	TARGET_ROOTFS
#################################################

# Target rootfs
export LF_TARGET_ROOTFS=buildroot

# Buildroot defconfig
export RK_BUILDROOT_DEFCONFIG=luckfox_pico_vpn_defconfig

#################################################
# 	Defconfig
#################################################

# Target arch
export RK_ARCH=arm

# Target Toolchain Cross Compile
export RK_TOOLCHAIN_CROSS=arm-rockchip830-linux-uclibcgnueabihf

#misc image
export RK_MISC=wipe_all-misc.img

# Uboot defconfig
export RK_UBOOT_DEFCONFIG=luckfox_rv1106_uboot_defconfig

# Kernel defconfig
export RK_KERNEL_DEFCONFIG=luckfox_rv1106_linux_defconfig

# Kernel defconfig fragment (netdev LED trigger, NEON crypto, no WireGuard debug)
export RK_KERNEL_DEFCONFIG_FRAGMENT=luckfox_rv1106-vpn.config

# No camera sensor IQ / CAC files, no rockchip test

#################################################
# 	PRE and POST
#################################################

# specify pre.sh for delete/overlay files
export RK_PRE_BUILD_OEM_SCRIPT=luckfox-buildroot-oem-pre.sh

# specify post.sh for delete/overlay files
export RK_PRE_BUILD_USERDATA_SCRIPT=luckfox-userdata-pre.sh

# remove camera/telnet/test init scripts (runs before the overlays are copied)
export RK_POST_BUILD_SCRIPT=luckfox-vpn-post.sh

# declare overlay directory (overlay-luckfox-vpn last: it overrides sshd_config)
export RK_POST_OVERLAY="overlay-luckfox-config overlay-luckfox-buildroot-init overlay-luckfox-buildroot-shadow overlay-luckfox-vpn"
