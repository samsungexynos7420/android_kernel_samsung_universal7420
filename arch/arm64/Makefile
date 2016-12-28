#
# arch/arm64/Makefile
#
# This file is included by the global makefile so that you can add your own
# architecture-specific flags and dependencies.
#
# This file is subject to the terms and conditions of the GNU General Public
# License.  See the file "COPYING" in the main directory of this archive
# for more details.
#
# Copyright (C) 1995-2001 by Russell King

ifeq ($(CONFIG_RELOCATABLE_KERNEL), y) 
LDFLAGS_vmlinux	:=-p --no-undefined -X -pie -Bsymbolic
else 
LDFLAGS_vmlinux	:=--no-undefined -X
endif 

CPPFLAGS_vmlinux.lds = -DTEXT_OFFSET=$(TEXT_OFFSET)
OBJCOPYFLAGS	:=-O binary -R .note -R .note.gnu.build-id -R .comment -S
GZFLAGS		:=-9

LIBGCC 		:= $(shell $(CC) $(KBUILD_CFLAGS) -print-libgcc-file-name)

KBUILD_DEFCONFIG := defconfig

KBUILD_CFLAGS	+= -mgeneral-regs-only
KBUILD_CFLAGS	+= -fno-pic
KBUILD_CFLAGS	+= $(call cc-option, -mpc-relative-literal-loads)

ifeq ($(CONFIG_CC_STACKPROTECTOR),y)
KBUILD_CFLAGS	+=-fstack-protector-all
endif

ifeq ($(CONFIG_CPU_BIG_ENDIAN), y)
KBUILD_CPPFLAGS	+= -mbig-endian
AS		+= -EB
LD		+= -EB
else
KBUILD_CPPFLAGS	+= -mlittle-endian
AS		+= -EL
LD		+= -EL
endif

comma = ,

CHECKFLAGS	+= -D__aarch64__

# exynos
machine-$(CONFIG_ARCH_EXYNOS)		+= exynos
plat-y		+= samsung
ifneq ($(machine-y),)
MACHINE  := arch/arm64/mach-$(word 1,$(machine-y))/
else
MACHINE  :=
endif
machdirs := $(patsubst %,arch/arm64/mach-%/,$(machine-y))
platdirs := $(patsubst %,arch/arm64/plat-%/,$(plat-y))
KBUILD_CPPFLAGS += $(patsubst %, -I%include,$(machdirs) $(platdirs))

ifeq ($(CONFIG_ARM64_ERRATUM_843419), y)
KBUILD_CFLAGS_MODULE	+= -mcmodel=large
endif

# Default value
head-y		:= arch/arm64/kernel/head.o

# The byte offset of the kernel image in RAM from the start of RAM.
TEXT_OFFSET := 0x00205000

export	TEXT_OFFSET GZFLAGS

core-y		+= arch/arm64/kernel/ arch/arm64/mm/
core-$(CONFIG_CRYPTO) += arch/arm64/crypto/
core-y		+= $(machdirs) $(platdirs)
libs-y		:= arch/arm64/lib/ $(libs-y)
libs-y		+= $(LIBGCC)

suffix_$(CONFIG_KERNEL_GZIP) = gz
suffix_$(CONFIG_KERNEL_LZ4)  = lz4

# Default target when executing plain make
ifeq ($(CONFIG_BUILD_ARM64_APPENDED_DTB_IMAGE),y)
KBUILD_IMAGE	:= Image.$(suffix_y)-dtb
else
KBUILD_IMAGE	:= Image.$(suffix_y)
endif

KBUILD_DTBS	:= dtbs

all:	$(KBUILD_IMAGE) $(KBUILD_DTBS)

boot := arch/arm64/boot

Image Image.gz: vmlinux scripts dtbs
	$(Q)$(MAKE) $(build)=$(boot) $(boot)/$@

zinstall install: vmlinux
	$(Q)$(MAKE) $(build)=$(boot) $@

%.dtb: scripts
	$(Q)$(MAKE) $(build)=$(boot)/dts $(boot)/dts/$@

dtbs: scripts
	$(Q)$(MAKE) $(build)=$(boot)/dts dtbs

PHONY += vdso_install
vdso_install:
	$(Q)$(MAKE) $(build)=arch/arm64/kernel/vdso $@

Image-dtb Image.gz-dtb Image.lz4-dtb: vmlinux scripts dtbs
	$(Q)$(MAKE) $(build)=$(boot) $(boot)/$@

# We use MRPROPER_FILES and CLEAN_FILES now
archclean:
	$(Q)$(MAKE) $(clean)=$(boot)

define archhelp
  echo  '* Image.gz      - Compressed kernel image (arch/$(ARCH)/boot/Image.gz)'
  echo  '* Image.lz4      - Compressed kernel image (arch/$(ARCH)/boot/Image.lz4)'
  echo  '  Image         - Uncompressed kernel image (arch/$(ARCH)/boot/Image)'
  echo  '* dtbs          - Build device tree blobs for enabled boards'
  echo  '  install       - Install uncompressed kernel'
  echo  '  zinstall      - Install compressed kernel'
  echo  '                  Install using (your) ~/bin/installkernel or'
  echo  '                  (distribution) /sbin/installkernel or'
  echo  '                  install to $$(INSTALL_PATH) and run lilo'
endef
