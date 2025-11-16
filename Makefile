# HURRICANE v6-gatewayd Makefile
# High-performance IPv6 tunnel gateway daemon with CNSA 2.0 crypto

CC = gcc
CFLAGS = -Wall -Wextra -O2 -std=gnu11 -D_GNU_SOURCE
LDFLAGS = -lpthread -lm -lssl -lcrypto

# Check for liboqs
LIBOQS_AVAILABLE := $(shell pkg-config --exists liboqs && echo yes || echo no)
ifeq ($(LIBOQS_AVAILABLE),yes)
    CFLAGS += -DHAVE_LIBOQS $(shell pkg-config --cflags liboqs)
    LDFLAGS += $(shell pkg-config --libs liboqs)
    $(info Building with liboqs support (CNSA 2.0 compliant))
else
    $(warning liboqs not found - using OpenSSL fallback)
    $(warning For full CNSA 2.0 compliance, install liboqs)
endif

# Check for PAM (hardware authentication)
LIBPAM_AVAILABLE := $(shell pkg-config --exists pam && echo yes || echo no)
ifeq ($(LIBPAM_AVAILABLE),yes)
    CFLAGS += -DHAVE_LIBPAM
    LDFLAGS += -lpam
    $(info Building with PAM support (hardware authentication))
else
    $(warning libpam not found - hardware authentication disabled)
endif

# Check for libfprint (fingerprint reader)
LIBFPRINT_AVAILABLE := $(shell pkg-config --exists libfprint-2 && echo yes || echo no)
ifeq ($(LIBFPRINT_AVAILABLE),yes)
    CFLAGS += -DHAVE_LIBFPRINT $(shell pkg-config --cflags libfprint-2)
    LDFLAGS += $(shell pkg-config --libs libfprint-2)
    $(info Building with libfprint support (fingerprint authentication))
else
    $(warning libfprint not found - fingerprint authentication disabled)
endif

# Check for libcurl (for he-update utility)
LIBCURL_AVAILABLE := $(shell pkg-config --exists libcurl && echo yes || echo no)
ifeq ($(LIBCURL_AVAILABLE),yes)
    $(info Building with libcurl support (he-update utility enabled))
else
    $(warning libcurl not found - he-update utility disabled)
    $(warning For Hurricane Electric auto-update support, install libcurl4-openssl-dev)
endif

# Check for libykpers (YubiKey)
LIBYKPERS_AVAILABLE := $(shell pkg-config --exists ykpers-1 && echo yes || echo no)
ifeq ($(LIBYKPERS_AVAILABLE),yes)
    CFLAGS += -DHAVE_LIBYKPERS $(shell pkg-config --cflags ykpers-1)
    LDFLAGS += $(shell pkg-config --libs ykpers-1)
    $(info Building with YubiKey support)
else
    $(warning libykpers not found - YubiKey authentication disabled)
endif

PREFIX = /usr/local
BINDIR = $(PREFIX)/bin
SYSCONFDIR = /etc
STATEDIR = /var/lib/v6-gatewayd
SYSTEMDDIR = /etc/systemd/system
WEBDIR = $(PREFIX)/share/v6-gatewayd/web

# Source files
SRCDIR = src
INCDIR = include
OBJDIR = obj

# Daemon sources (exclude v6gw-keygen.c and he-update.c)
DAEMON_SOURCES = $(filter-out $(SRCDIR)/v6gw-keygen.c $(SRCDIR)/he-update.c, $(wildcard $(SRCDIR)/*.c))
DAEMON_OBJECTS = $(DAEMON_SOURCES:$(SRCDIR)/%.c=$(OBJDIR)/%.o)

# Keygen sources (main + shared modules)
KEYGEN_OBJECTS = $(OBJDIR)/v6gw-keygen.o $(OBJDIR)/crypto.o $(OBJDIR)/log.o

TARGET_DAEMON = v6-gatewayd
TARGET_KEYGEN = v6gw-keygen
TARGET_HEUPDATE = he-update

# Header dependencies
INCLUDES = -I$(INCDIR)

.PHONY: all clean install uninstall dirs

ifeq ($(LIBCURL_AVAILABLE),yes)
all: dirs $(TARGET_DAEMON) $(TARGET_KEYGEN) $(TARGET_HEUPDATE)
else
all: dirs $(TARGET_DAEMON) $(TARGET_KEYGEN)
endif

dirs:
	@mkdir -p $(OBJDIR)

$(TARGET_DAEMON): $(DAEMON_OBJECTS)
	$(CC) $(DAEMON_OBJECTS) -o $@ $(LDFLAGS)
	@echo "Built $(TARGET_DAEMON) successfully"

$(TARGET_KEYGEN): $(KEYGEN_OBJECTS)
	$(CC) $(KEYGEN_OBJECTS) -o $@ $(LDFLAGS)
	@echo "Built $(TARGET_KEYGEN) successfully"

ifeq ($(LIBCURL_AVAILABLE),yes)
$(TARGET_HEUPDATE): $(OBJDIR)/he-update.o
	$(CC) $(OBJDIR)/he-update.o -o $@ -lcurl
	@echo "Built $(TARGET_HEUPDATE) successfully"

$(OBJDIR)/he-update.o: $(SRCDIR)/he-update.c
	$(CC) $(CFLAGS) -c $< -o $@
endif

$(OBJDIR)/%.o: $(SRCDIR)/%.c
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

clean:
	rm -rf $(OBJDIR) $(TARGET_DAEMON) $(TARGET_KEYGEN) $(TARGET_HEUPDATE)
	@echo "Cleaned build artifacts"

ifeq ($(LIBCURL_AVAILABLE),yes)
install: $(TARGET_DAEMON) $(TARGET_KEYGEN) $(TARGET_HEUPDATE)
else
install: $(TARGET_DAEMON) $(TARGET_KEYGEN)
endif
	@echo "Installing v6-gatewayd with CNSA 2.0 crypto..."
	install -D -m 755 $(TARGET_DAEMON) $(BINDIR)/$(TARGET_DAEMON)
	install -D -m 755 $(TARGET_KEYGEN) $(BINDIR)/$(TARGET_KEYGEN)
ifeq ($(LIBCURL_AVAILABLE),yes)
	install -D -m 755 $(TARGET_HEUPDATE) $(BINDIR)/$(TARGET_HEUPDATE)
	install -D -m 644 systemd/he-update.service $(SYSTEMDDIR)/he-update.service
	install -D -m 644 systemd/he-update.timer $(SYSTEMDDIR)/he-update.timer
	install -D -m 644 config/v6-gatewayd-he.env.example $(SYSCONFDIR)/v6-gatewayd-he.env.example
endif
	install -D -m 644 config/v6-gatewayd.conf.example $(SYSCONFDIR)/v6-gatewayd.conf.example
	install -D -m 644 systemd/v6-gatewayd.service $(SYSTEMDDIR)/v6-gatewayd.service
	install -D -m 644 web/index.html $(WEBDIR)/index.html
	mkdir -p $(STATEDIR)
	@echo "Installation complete!"
	@echo "1. Generate CNSA 2.0 keys:"
	@echo "     sudo $(BINDIR)/$(TARGET_KEYGEN) -o $(STATEDIR)/keys.bin"
	@echo "2. Copy and edit configuration:"
	@echo "     sudo cp $(SYSCONFDIR)/v6-gatewayd.conf.example $(SYSCONFDIR)/v6-gatewayd.conf"
	@echo "3. Enable cryptography in config:"
	@echo "     crypto_enabled = true"
	@echo "     crypto_keyfile = $(STATEDIR)/keys.bin"
	@echo "4. Start the service:"
	@echo "     sudo systemctl daemon-reload"
	@echo "     sudo systemctl enable v6-gatewayd"
	@echo "     sudo systemctl start v6-gatewayd"
ifeq ($(LIBCURL_AVAILABLE),yes)
	@echo ""
	@echo "Optional: Configure Hurricane Electric auto-update (for dynamic IPs):"
	@echo "5. Setup HE credentials:"
	@echo "     sudo cp $(SYSCONFDIR)/v6-gatewayd-he.env.example $(SYSCONFDIR)/v6-gatewayd-he.env"
	@echo "     sudo nano $(SYSCONFDIR)/v6-gatewayd-he.env"
	@echo "     sudo chmod 600 $(SYSCONFDIR)/v6-gatewayd-he.env"
	@echo "6. Enable auto-update timer:"
	@echo "     sudo systemctl enable he-update.timer"
	@echo "     sudo systemctl start he-update.timer"
endif

uninstall:
	rm -f $(BINDIR)/$(TARGET_DAEMON)
	rm -f $(BINDIR)/$(TARGET_KEYGEN)
	rm -f $(BINDIR)/$(TARGET_HEUPDATE)
	rm -f $(SYSTEMDDIR)/v6-gatewayd.service
	rm -f $(SYSTEMDDIR)/he-update.service
	rm -f $(SYSTEMDDIR)/he-update.timer
	@echo "Uninstalled v6-gatewayd (config and state preserved)"

# Development targets
debug: CFLAGS += -g -DDEBUG -O0
debug: clean all

.PHONY: help
help:
	@echo "HURRICANE v6-gatewayd Build System"
	@echo ""
	@echo "Targets:"
	@echo "  all       - Build the daemon (default)"
	@echo "  clean     - Remove build artifacts"
	@echo "  install   - Install to system (requires root)"
	@echo "  uninstall - Remove from system (requires root)"
	@echo "  debug     - Build with debug symbols"
	@echo "  help      - Show this help"
