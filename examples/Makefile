# This Makefile assumes the top folder has been built

TOP = ..
CC ?= gcc

CEEUTILS_DIR := $(TOP)/cee-utils
COMMON_DIR   := $(TOP)/common

BOT_DISCORD := bot-audit-log \
               bot-ban \
               bot-channel \
               bot-components \
               bot-delete-messages \
               bot-echo \
               bot-embed \
               bot-emoji \
               bot-fetch-messages \
               bot-guild-template \
               bot-guild \
               bot-invite \
               bot-manual-dm \
               bot-pin \
               bot-ping-pong \
               bot-presence \
               bot-reaction \
               bot-shell \
               bot-slash-commands \
               bot-slash-commands2 \
               bot-voice \
               bot-webhook

BOT_GITHUB  := bot-github-create-fork \
               bot-github-get-gist \
               bot-github-gist-starred \
               bot-github-gist

BOTS := $(BOT_DISCORD) $(BOT_GITHUB)

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

all: $(BOTS)

$(BOT_DISCORD): %: %.c
	$(CC) $(CFLAGS) -o $@ $< -ldiscord $(LDFLAGS)
$(BOT_GITHUB): %: %.c
	$(CC) $(CFLAGS) -o $@ $< -lgithub $(LDFLAGS)

echo:
	@ echo -e 'CC: $(CC)\n'
	@ echo -e 'BOT_DISCORD: $(BOT_DISCORD)\n'
	@ echo -e 'BOT_GITHUB: $(BOT_GITHUB)\n'

clean:
	rm -rf $(BOTS)

.PHONY: all echo clean
