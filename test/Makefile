# This Makefile assumes the top folder has been built

TOP = ..
CC ?= gcc

CEEUTILS_DIR := $(TOP)/cee-utils
COMMON_DIR    := $(TOP)/common

TEST_DISCORD := test-discord-api test-discord-async test-discord-ws
TEST_GITHUB  := test-git2
TEST_COMMON  := test-user-agent test-websockets

EXES := $(TEST_DISCORD) $(TEST_GITHUB) $(TEST_COMMON)

CFLAGS  += -I$(TOP) -I$(CEEUTILS_DIR) -I$(COMMON_DIR) \
           -I$(COMMON_DIR)/third-party                \
           -O0 -g -pthread -Wall
LDFLAGS += -L$(TOP)/lib

ifneq (,$(findstring $(CC),stensal-c sfc)) # ifeq stensal-c OR sfc
	__DEST  := $(dir $(shell which $(CC)))
	PREFIX  := $(__DEST:%/stensal/bin/=%/usr)
	LDFLAGS += -lcurl-bearssl -lbearssl -static
else
	LDFLAGS += $(pkg-config --libs --cflags libcurl) -lcurl
endif

all: $(EXES)

$(TEST_DISCORD): %: %.c
	$(CC) $(CFLAGS) -o $@ $< -ldiscord $(LDFLAGS)
$(TEST_GITHUB): %: %.c
	$(CC) $(CFLAGS) -o $@ $< -lgithub $(LDFLAGS)
$(TEST_COMMON): %: %.c
	$(CC) $(CFLAGS) -o $@ $< -ldiscord $(LDFLAGS)

echo:
	@ echo -e 'CC: $(CC)\n'
	@ echo -e 'EXES: $(EXES)\n'

clean:
	rm -rf $(EXES)

.PHONY: all echo clean
