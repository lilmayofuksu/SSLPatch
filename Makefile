export TARGET=iphone:clang:6.0
include $(THEOS)/makefiles/common.mk

IPHONE_ARCHS = armv7
TWEAK_NAME = SSLPatch_CVE-2014-1266
TARGET_IPHONEOS_DEPLOYMENT_VERSION = 6.0

SSLPatch_CVE-2014-1266_FILES = Tweak.x minimal.c ssl_hooks.c sslAesGcmCipher.c cc/cc.c cc/ccaes_gcm_mode.c ccaes_gcm.c
SSLPatch_CVE-2014-1266_CFLAGS = -fvisibility=hidden -D__SSLPATCH_NO_ASM__ -I. -Icc/
SSLPatch_CVE-2014-1266_LIBRARIES = substrate
SSLPatch_CVE-2014-1266_FRAMEWORKS = Security

include $(THEOS_MAKE_PATH)/tweak.mk

stage::
        -plutil -convert binary1 "$(THEOS_STAGING_DIR)/Library/MobileSubstrate/DynamicLibraries/$(TWEAK_NAME).plist"