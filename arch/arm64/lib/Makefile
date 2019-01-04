lib-y		:= bitops.o checksum.o clear_user.o delay.o 	\
		   copy_from_user.o copy_to_user.o copy_in_user.o copy_page.o	\
		   clear_page.o memchr.o memcpy.o memmove.o memset.o	\
		   memcmp.o strcmp.o strncmp.o strlen.o strnlen.o	\
		   strchr.o strrchr.o

ifeq ($(CONFIG_KERNEL_MODE_NEON), y)
CFLAGS_xor-neon.o += $(DISABLE_LTO)
CFLAGS_xor-neon.o += $(call cc-option, -fno-whole-program)
obj-$(CONFIG_XOR_BLOCKS)	+= xor-neon.o
CFLAGS_REMOVE_xor-neon.o	+= -mgeneral-regs-only
CFLAGS_xor-neon.o		+= -ffreestanding
endif

obj-$(CONFIG_CRC32) += crc32.o
