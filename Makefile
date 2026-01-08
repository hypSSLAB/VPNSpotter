CC = gcc
CFLAGS =
DEBUG_FLAGS = -O0 -g
LDFLAGS = -lpcap -lm

API_DIR = ./api
MAIN_DIR = ./main
INSTALL_DIR = $(HOME)/local/bin

API_SOURCES = $(wildcard $(API_DIR)/*.c)

EXCLUDE_SOURCES = openvpn_fingerprint #vpnspotter

EXCLUDE_SOURCES_WITH_PATH = $(addprefix $(MAIN_DIR)/,$(addsuffix .c,$(EXCLUDE_SOURCES)))
MAIN_SOURCES = $(filter-out $(EXCLUDE_SOURCES_WITH_PATH), $(wildcard $(MAIN_DIR)/*.c))
MAIN_TARGETS = $(patsubst $(MAIN_DIR)/%.c,%,$(MAIN_SOURCES))

CLEAN_TARGETS = $(MAIN_TARGETS) $(EXCLUDE_SOURCES)

.PHONY: all
all: $(MAIN_TARGETS)

$(MAIN_TARGETS): %: $(MAIN_DIR)/%.c $(API_SOURCES)
	$(CC) $(CFLAGS) $(MAIN_DIR)/$*.c $(API_SOURCES) -o $@ $(LDFLAGS)

.PHONY: time
time:
	@for target in $(MAIN_TARGETS); do \
		$(CC) -DTIME $(MAIN_DIR)/$$target.c $(API_SOURCES) -o $$target $(LDFLAGS); \
	done

.PHONY: debug
debug:
	@for target in $(MAIN_TARGETS); do \
		$(CC) $(DEBUG_FLAGS) -DDEBUG $(MAIN_DIR)/$$target.c $(API_SOURCES) -o $$target $(LDFLAGS); \
	done

.PHONY: debug_log
debug_log:
	@for target in $(MAIN_TARGETS); do \
		$(CC) $(DEBUG_FLAGS) -DDEBUG_LOG $(MAIN_DIR)/$$target.c $(API_SOURCES) -o $$target $(LDFLAGS); \
	done

.PHONY: debug_all
debug_all:
	@for target in $(MAIN_TARGETS); do \
		$(CC) $(DEBUG_FLAGS) -DDEBUG -DDEBUG_LOG $(MAIN_DIR)/$$target.c $(API_SOURCES) -o $$target $(LDFLAGS); \
	done

.PHONY: install
install: all
	@echo "Installing binaries to $(INSTALL_DIR)..."
	@mkdir -p $(INSTALL_DIR)
	@for target in $(MAIN_TARGETS); do \
		rm -f $(INSTALL_DIR)/$$target; \
		cp $$target $(INSTALL_DIR)/; \
		echo "Installed $$target to $(INSTALL_DIR)"; \
	done

.PHONY: clean
clean:
	rm -f $(CLEAN_TARGETS)
	rm -rf pcap_tmp*
	rm -f *.txt