# Compiler settings
CC = gcc
CFLAGS = -Wall -Wextra -O2

# Libraries to link
LDLIBS = -lpcap

# Target executable name
TARGET = cts_inject

# Source files
SRC = cts_inject.c

# Default target
all: $(TARGET)

# Rule to build the target
$(TARGET): $(SRC)
	$(CC) $(CFLAGS) $(SRC) -o $(TARGET) $(LDLIBS)

# Rule to clean up compiled files
clean:
	rm -f $(TARGET)