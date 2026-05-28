/*
 * ld script to make ARM Linux kernel
 * taken from the i386 version by Russell King
 * Written by Martin Mares <mj@atrey.karlin.mff.cuni.cz>
 */

#include <asm-generic/vmlinux.lds.h>
#include <asm/kernel-pgtable.h>
#include <asm/thread_info.h>
#include <asm/memory.h>
#include <asm/page.h>
#include <asm/pgtable.h>

#if (defined(CONFIG_GENERIC_BUG))
#define ARM_EXIT_KEEP(x)        x
#define ARM_EXIT_DISCARD(x)
#else
#define ARM_EXIT_KEEP(x)
#define ARM_EXIT_DISCARD(x)	x
#endif

OUTPUT_ARCH(aarch64)
ENTRY(_text)

jiffies = jiffies_64;

#ifdef CONFIG_UNMAP_KERNEL_AT_EL0
#define TRAMP_TEXT					\
	. = ALIGN(PAGE_SIZE);				\
	VMLINUX_SYMBOL(__entry_tramp_text_start) = .;	\
	*(.entry.tramp.text)				\
	. = ALIGN(PAGE_SIZE);				\
	VMLINUX_SYMBOL(__entry_tramp_text_end) = .;
#else
#define TRAMP_TEXT
#endif

#ifdef CONFIG_DEBUG_ALIGN_RODATA
#define ALIGN_DEBUG_RO			. = ALIGN(1<<SECTION_SHIFT);
#define ALIGN_DEBUG_RO_MIN(min)		ALIGN_DEBUG_RO
#else
#define ALIGN_DEBUG_RO
#define ALIGN_DEBUG_RO_MIN(min)		. = ALIGN(min);
#endif

SECTIONS
{
	/*
	 * XXX: The linker does not define how output sections are
	 * assigned to input sections when there are multiple statements
	 * matching the same input section name.  There is no documented
	 * order of matching.
	 */
	/DISCARD/ : {
		ARM_EXIT_DISCARD(EXIT_TEXT)
		ARM_EXIT_DISCARD(EXIT_DATA)
		EXIT_CALL
		*(.discard)
		*(.discard.*)
	}

	. = PAGE_OFFSET + TEXT_OFFSET;

	.head.text : {
		_text = .;
		HEAD_TEXT
	}
	ALIGN_DEBUG_RO
	.text : {			/* Real text segment		*/
		_stext = .;		/* Text and read-only data	*/
			__exception_text_start = .;
			*(.exception.text)
			__exception_text_end = .;
			IRQENTRY_TEXT
			TEXT_TEXT
			SCHED_TEXT
			LOCK_TEXT
			TRAMP_TEXT
			*(.fixup)
			*(.gnu.warning)
		. = ALIGN(16);
		*(.got)			/* Global offset table		*/
	}

#ifdef CONFIG_TIMA_RKP
	. = ALIGN(PAGE_SIZE);
	.rkp.bitmap : {
		rkp_pgt_bitmap = .;
		. = rkp_pgt_bitmap + 0x20000;
	}
	.rkp.dblmap : {
		rkp_map_bitmap = .;
		. = rkp_map_bitmap + 0x20000;
	}
#ifdef CONFIG_RKP_KDP
	 /* Creating a new section to store task credentials */
	. = ALIGN(PAGE_SIZE);
	.rkp.prot.page : {
		__rkp_ro_start = .;
	}
	. = ALIGN(PAGE_SIZE);
	. = ALIGN(1 << 21);
#endif /* CONFIG_RKP_KDP*/
#endif
	
	ALIGN_DEBUG_RO
	_etext = .;			/* End of text section */

	RO_DATA(PAGE_SIZE)
	EXCEPTION_TABLE(8)
	NOTES
	ALIGN_DEBUG_RO

	ALIGN_DEBUG_RO_MIN(PAGE_SIZE)
	__init_begin = .;
	.init.arch.info : {
		__arch_info_begin = .;
		*(.arch.info.init)
		__arch_info_end = .;
	}
#ifdef CONFIG_TIMA_RKP
	.vmm : { *(.vmm*) }
#endif
	INIT_TEXT_SECTION(8)
	.exit.text : {
		ARM_EXIT_KEEP(EXIT_TEXT)
	}

	ALIGN_DEBUG_RO_MIN(16)
	.init.data : {
		INIT_DATA
		INIT_SETUP(16)
		INIT_CALLS
		CON_INITCALL
		SECURITY_INITCALL
		INIT_RAM_FS
	}
	.exit.data : {
		ARM_EXIT_KEEP(EXIT_DATA)
	}

	PERCPU_SECTION(64)

#ifdef CONFIG_RELOCATABLE_KERNEL
	.rela : {
		. = ALIGN(8);
		__reloc_start = .;
		*(.rela .rela*)
		__reloc_end = .;
	}
	.dynsym : {
		. = ALIGN(8);
		__dynsym_start = .;
		*(.dynsym)
	}
#endif 

	. = ALIGN(4);
	.altinstructions : {
		__alt_instructions = .;
		*(.altinstructions)
		__alt_instructions_end = .;
	}
	.altinstr_replacement : {
		*(.altinstr_replacement)
	}

	. = ALIGN(PAGE_SIZE);
	__init_end = .;

	_data = .;
	_sdata = .;
	RW_DATA_SECTION(64, PAGE_SIZE, THREAD_SIZE)
	_edata = .;

	BSS_SECTION(0, 0, 0)

	. = ALIGN(PAGE_SIZE);
	idmap_pg_dir = .;
	. += IDMAP_DIR_SIZE;
	swapper_pg_dir = .;
	. += SWAPPER_DIR_SIZE;

#ifdef CONFIG_ARM64_SW_TTBR0_PAN
	reserved_ttbr0 = .;
	. += RESERVED_TTBR0_SIZE;
#endif

#ifdef CONFIG_UNMAP_KERNEL_AT_EL0
	tramp_pg_dir = .;
	. += PAGE_SIZE;
#endif

	_end = .;

	STABS_DEBUG
	.comment 0 : { *(.comment) }
}

#ifdef CONFIG_UNMAP_KERNEL_AT_EL0
ASSERT((__entry_tramp_text_end - __entry_tramp_text_start) == PAGE_SIZE,
	"Entry trampoline text too big")
#endif
