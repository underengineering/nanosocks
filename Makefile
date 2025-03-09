CC = gcc
LD = gcc
CFLAGS ?= -O3
LDFLAGS ?=

BUILD_DIR ?= build

USE_SYSTEM_CARES ?= 1
CARES_VERSION ?= 1.34.4
CARES_BUILD_DIR = $(BUILD_DIR)/c-ares-$(CARES_VERSION)
CARES_INSTALL_DIR = $(BUILD_DIR)/cares-install
CARES_TARBALL = $(CARES_BUILD_DIR).tar.gz
CARES_URL = https://github.com/c-ares/c-ares/releases/download/v$(CARES_VERSION)/c-ares-$(CARES_VERSION).tar.gz

HEADERS = $(addprefix src/, client.h list.h log.h protocol.h server.h util.h)
OBJECTS = $(addprefix $(BUILD_DIR)/, client.o nanosocks.o server.o)
ifeq ($(USE_SYSTEM_CARES),1)
	LDFLAGS += -lcares
else
	CFLAGS += -I$(CARES_INSTALL_DIR)/include
	LDFLAGS += -L$(CARES_INSTALL_DIR)/lib -lcares
	DEPENDENCIES += $(CARES_INSTALL_DIR)/lib/libcares.a
endif

.PHONY: all
all: $(OBJECTS)
	$(LD) $(LDFLAGS) $^ -o $(BUILD_DIR)/nanosocks

$(OBJECTS): $(BUILD_DIR)/%.o: src/%.c $(HEADERS)
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) -std=c99 -D_GNU_SOURCE -c $< -o $@

$(CARES_INSTALL_DIR)/lib/libcares.a: $(CARES_TARBALL)
	@echo "Building c-ares $(CARES_VERSION)..."
	mkdir -p $(CARES_INSTALL_DIR)
	# Extract tarball into build directory
	tar -xzf $(CARES_TARBALL) -C $(BUILD_DIR)
	@if [ ! -d "$(CARES_BUILD_DIR)" ]; then \
	  mv $(BUILD_DIR)/c-ares-$(CARES_VERSION) $(CARES_BUILD_DIR); \
	fi
	cd $(CARES_BUILD_DIR) && ./configure --disable-shared --prefix=$(abspath $(CARES_INSTALL_DIR))
	cd $(CARES_BUILD_DIR) && $(MAKE)
	cd $(CARES_BUILD_DIR) && $(MAKE) install

$(CARES_TARBALL):
	mkdir -p $(BUILD_DIR)
	curl -L $(CARES_URL) -o $(CARES_TARBALL)

.PHONY: clean
clean:
	rm -rf $(BUILD_DIR)

