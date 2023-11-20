CC           = gcc
obj          = $(addprefix $(BUILD_DIR)/, encfs.o crypt.o access.o)
CFLAGSFUSE   = `pkg-config fuse --cflags`
LLIBSFUSE    = `pkg-config fuse --libs`
LLIBSGMSSL   = -lgmssl
LLIBSOPENSSL = -lcrypto

CFLAGS = -c -std=c11 -g -Wall -Wextra
LFLAGS = -L/usr/lib/ -L/usr/local/lib

ENCFUSE = encfs

LOG_DIR = log
BUILD_DIR = build
BIN_DIR = bin
MNT_DIR = mnt

$(BUILD_DIR):
	@if [ ! -d "build" ]; then \
		echo "Directory 'build' does not exist, creating..."; \
		mkdir build; \
	fi

$(LOG_DIR):
	@if [ ! -d "log" ]; then \
		echo "Directory 'log' does not exist, creating..."; \
		mkdir log; \
	fi

$(BIN_DIR):
	@if [ ! -d "bin" ]; then \
		echo "Directory 'bin' does not exist, creating..."; \
		mkdir bin; \
	fi

$(MNT_DIR):
	@if [ ! -d "mnt" ]; then \
		echo "Directory 'mnt' does not exist, creating..."; \
		mkdir mnt; \
	fi

$(BUILD_DIR)/%.o: %.c
	$(CC) $(CFLAGS) $(CFLAGSFUSE) $< -o $@

$(BIN_DIR)/$(ENCFUSE): $(obj)
	$(CC) $(LFLAGS) $^ -o $@ $(LLIBSFUSE) $(LLIBSOPENSSL) $(LLIBSGMSSL)

.PHONY: all clean

all: $(BUILD_DIR) $(LOG_DIR) $(BIN_DIR) $(BIN_DIR)/$(ENCFUSE)

clean:
	rm -rf $(BUILD_DIR)/*
	rm -f $(BIN_DIR)/*
	rm -f $(LOG_DIR)/*



