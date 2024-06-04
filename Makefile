# NATMap by heiher <https://github.com/heiher/natmap>
# Copyright (C) 2023 muink <https://github.com/muink>
#
# This is free software, licensed under the Apache License, Version 2.0

include $(TOPDIR)/rules.mk

LUCI_NAME:=luci-app-natmapt
PKG_VERSION:=20240603

LUCI_TITLE:=LuCI Support for natmap
LUCI_PKGARCH:=all
LUCI_DEPENDS:=+natmapt +coreutils-timeout

LUCI_DESCRIPTION:=TCP/UDP port mapping for full cone NAT

PKG_LICENSE:=Apache-2.0
PKG_MAINTAINER:=Anya Lin <hukk1996@gmail.com>, Richard Yu <yurichard3839@gmail.com>

include $(TOPDIR)/feeds/luci/luci.mk

# call BuildPackage - OpenWrt buildroot signature
