#
# arch/x86/sev/Makefile
#
# This file is subject to the terms and conditions of the GNU General Public
# License.  See the file "COPYING" in the main directory of this archive
# for more details.
#

# Sanitizer runtimes are unavailable and cannot be linked here.
KASAN_SANITIZE			:= n
KCSAN_SANITIZE			:= n
OBJECT_FILES_NON_STANDARD	:= y

# Prevents link failures: __sanitizer_cov_trace_pc() is not linked in.
KCOV_INSTRUMENT		:= n

always-y := ap_jump_table.bin

ap_jump_table-y				+= ap_jump_table.o

targets	+= $(ap_jump_table-y)

APJUMPTABLE_OBJS = $(addprefix $(obj)/,$(ap_jump_table-y))

LDFLAGS_ap_jump_table.elf := -m elf_i386 -T

targets += ap_jump_table.elf
$(obj)/ap_jump_table.elf: $(obj)/ap_jump_table.lds $(APJUMPTABLE_OBJS) FORCE
	$(call if_changed,ld)

OBJCOPYFLAGS_ap_jump_table.bin := -O binary

targets += ap_jump_table.bin
$(obj)/ap_jump_table.bin: $(obj)/ap_jump_table.elf FORCE
	$(call if_changed,objcopy)

# ---------------------------------------------------------------------------

KBUILD_AFLAGS	:= $(REALMODE_CFLAGS) -D__ASSEMBLY__
GCOV_PROFILE := n
UBSAN_SANITIZE := n
