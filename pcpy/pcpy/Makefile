CC=g++
CFLAGS=-I. -lpcap
DEPS = main.cpp PcapManager.h PcapManager.cpp
OBJ = main.o PcapManager.o

%.o: %.c $(DEPS)
        $(CC) -c -o $@ $< $(CFLAGS)

main: $(OBJ)
        $(CC) -o $@ $^ $(CFLAGS)


