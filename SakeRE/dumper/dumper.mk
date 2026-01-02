# Cross compiler for ARM64 architecture
CC = aarch64-linux-gnu-gcc
CFLAGS = -Wall -O2 -static -fPIC
LDFLAGS = -static
LIBS =

# Output binary and source file
TARGET = dumper
SRC = dumper.c

# Compilation and linking rules
all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) $(SRC) -o $(TARGET) $(LDFLAGS) $(LIBS)

clean:
	rm -f $(TARGET)

