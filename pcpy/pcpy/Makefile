# Makefile
CC=g++
CFLAGS=-I. -lpcap
DEPS = main.cpp PcapManager.h PcapManager.cpp log.h log.cpp
OBJ = main.o PcapManager.o log.o

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

main: $(OBJ)
	$(CC) -o $@ $^ $(CFLAGS)
