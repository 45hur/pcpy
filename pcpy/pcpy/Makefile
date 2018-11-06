CC=gcc
CFLAGS=-I. -lpcap
DEPS = main.cpp PcapManager.h PcapManager.cpp
OBJ = pcpy.o

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

program: $(OBJ)
	$(CC) -o $@ $^ $(CFLAGS)
