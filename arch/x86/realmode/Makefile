#
# arch/x86/realmode/Makefile
#
# This file is subject to the terms and conditions of the GNU General Public
# License.  See the file "COPYING" in the main directory of this archive
# for more details.
#
#

# Sanitizer runtimes are unavailable and cannot be linked here.
KASAN_SANITIZE			:= n
KCSAN_SANITIZE			:= n
OBJECT_FILES_NON_STANDARD	:= y

RMPIGGY-y				 = $(obj)/rm/realmode.bin
RMPIGGY-$(CONFIG_AMD_MEM_ENCRYPT)	+= $(obj)/sev/ap_jump_table.bin

subdir- := rm
subdir- := sev

obj-y += init.o
obj-y += rmpiggy.o

$(obj)/rmpiggy.o: $(RMPIGGY-y)

$(obj)/rm/realmode.bin: FORCE
	$(Q)$(MAKE) $(build)=$(obj)/rm $@

$(obj)/sev/ap_jump_table.bin: FORCE
	$(Q)$(MAKE) $(build)=$(obj)/sev $@
