# HURRICANE v6-gatewayd Makefile
# High-performance IPv6 tunnel gateway daemon

CC = gcc
CFLAGS = -Wall -Wextra -O2 -std=gnu11 -D_GNU_SOURCE
LDFLAGS = -lpthread -lm
PREFIX = /usr/local
BINDIR = $(PREFIX)/bin
SYSCONFDIR = /etc
STATEDIR = /var/lib/v6-gatewayd
SYSTEMDDIR = /etc/systemd/system

# Source files
SRCDIR = src
INCDIR = include
OBJDIR = obj

SOURCES = $(wildcard $(SRCDIR)/*.c)
OBJECTS = $(SOURCES:$(SRCDIR)/%.c=$(OBJDIR)/%.o)
TARGET = v6-gatewayd

# Header dependencies
INCLUDES = -I$(INCDIR)

.PHONY: all clean install uninstall dirs

all: dirs $(TARGET)

dirs:
	@mkdir -p $(OBJDIR)

$(TARGET): $(OBJECTS)
	$(CC) $(OBJECTS) -o $@ $(LDFLAGS)
	@echo "Built $(TARGET) successfully"

$(OBJDIR)/%.o: $(SRCDIR)/%.c
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

clean:
	rm -rf $(OBJDIR) $(TARGET)
	@echo "Cleaned build artifacts"

install: $(TARGET)
	@echo "Installing v6-gatewayd..."
	install -D -m 755 $(TARGET) $(BINDIR)/$(TARGET)
	install -D -m 644 config/v6-gatewayd.conf.example $(SYSCONFDIR)/v6-gatewayd.conf.example
	install -D -m 644 systemd/v6-gatewayd.service $(SYSTEMDDIR)/v6-gatewayd.service
	mkdir -p $(STATEDIR)
	@echo "Installation complete. Copy example config and edit:"
	@echo "  sudo cp $(SYSCONFDIR)/v6-gatewayd.conf.example $(SYSCONFDIR)/v6-gatewayd.conf"
	@echo "  sudo systemctl daemon-reload"
	@echo "  sudo systemctl enable v6-gatewayd"

uninstall:
	rm -f $(BINDIR)/$(TARGET)
	rm -f $(SYSTEMDDIR)/v6-gatewayd.service
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
