CC = gcc
CFLAGS = -g -no-pie -fno-stack-protector -z execstack

SRC_DIR=src
BIN_DIR=bin

SOURCES := $(wildcard $(SRC_DIR)/*.c)
OBJECTS := $(patsubst $(SRC_DIR)/%.c, $(BIN_DIR)/%, $(SOURCES))

all: dossier $(OBJECTS)


$(BIN_DIR)/%: $(SRC_DIR)/%.c
	$(CC) -o $@ $^ $(CFLAGS) 

dossier:
	mkdir $(BIN_DIR)


clean:
	rm $(BIN_DIR)/*
