CC = gcc
CFLAGS = -g -no-pie -fno-stack-protector -z execstack

SRC_DIR=vuln_src
BIN_DIR=vuln_bin

SOURCES := $(wildcard $(SRC_DIR)/*.c)
OBJECTS := $(patsubst $(SRC_DIR)/%.c, $(BIN_DIR)/%, $(SOURCES))

all: $(OBJECTS)


$(BIN_DIR)/%: $(SRC_DIR)/%.c
	$(CC) -o $@ $^ $(CFLAGS) 


clean:
	rm $(BIN_DIR)/*
