# SPDX-License-Identifier: MIT
# Resident kaiHEN VFS + GameChat C-Button HBMenu plugin (/kaihen/plugins/nupvfs.nso)
.SUFFIXES:

ifeq ($(strip $(DEVKITPRO)),)
$(error "Please set DEVKITPRO in your environment")
endif

TOPDIR ?= $(CURDIR)
include $(DEVKITPRO)/libounce/switch2_rules

TARGET   := nupvfs
BUILD    := build
ARCH     := $(SWITCH2_CPU) -mtp=soft -fPIE

PORTLIBS_SW2 := $(DEVKITPRO)/portlibs/switch2
CFLAGS   := -g -Wall -Wextra -O2 -ffunction-sections -fdata-sections \
            $(ARCH) -D__SWITCH__ -D__SWITCH2__ -DNUPVFS_PLUGIN \
            -I$(CURDIR)/../source -I$(PORTLIBS_SW2)/include -I$(PORTLIBS)/include -I$(LIBNX)/include

LDFLAGS  := -specs=$(LIBNX)/switch.specs -g $(ARCH) -Wl,-Map,$(CURDIR)/$(BUILD)/$(TARGET).map
LIBS     := -lkaihen_plugin -lounce_core
LIBDIRS  := $(PORTLIBS_SW2) $(PORTLIBS) $(LIBNX)
LIBPATHS := $(foreach dir,$(LIBDIRS),-L$(dir)/lib)

SRCS     := $(CURDIR)/source/main.c $(CURDIR)/../source/vfs_romfs.c
OBJS     := $(BUILD)/main.o $(BUILD)/vfs_romfs.o

.PHONY: all clean

all: $(TARGET).nso

$(BUILD):
	@mkdir -p $(BUILD)

$(BUILD)/main.o: $(CURDIR)/source/main.c $(CURDIR)/../source/nupvfs_proto.h $(CURDIR)/../source/vfs_romfs.h | $(BUILD)
	@echo "[CC] plugin/source/main.c"
	@$(CC) $(CFLAGS) -c $< -o $@

$(BUILD)/vfs_romfs.o: $(CURDIR)/../source/vfs_romfs.c $(CURDIR)/../source/vfs_romfs.h $(CURDIR)/../source/nup.h | $(BUILD)
	@echo "[CC] source/vfs_romfs.c"
	@$(CC) $(CFLAGS) -c $< -o $@

$(TARGET).elf: $(OBJS)
	@echo "[LD] $@"
	@$(CC) $(LDFLAGS) $(OBJS) $(LIBPATHS) $(LIBS) -o $@

$(TARGET).nso: $(TARGET).elf
	@echo "[NSO] $@"
	@elf2nso $< $@

clean:
	@rm -rf $(BUILD) $(TARGET).elf $(TARGET).nso
