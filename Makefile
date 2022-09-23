CC = gcc
CFLAGS = -g -no-pie -fno-stack-protector -z execstack
IF_32 = -m32

SRC_DIR=src
BIN_DIR=bin

SOURCES := $(wildcard $(SRC_DIR)/*.c)
OBJECTS := $(patsubst $(SRC_DIR)/%.c, $(BIN_DIR)/%, $(SOURCES))

all: dossier $(OBJECTS)

64: dossier $(OBJECTS)

32: is_32 dossier $(OBJECTS)

is_32: 
	$(eval CFLAGS := $(CFLAGS) $(IF_32))

$(BIN_DIR)/%: $(SRC_DIR)/%.c
	$(CC) -o $@ $^ $(CFLAGS) 

dossier:
	mkdir -p $(BIN_DIR)


clean:
	rm $(BIN_DIR)/*
