TARGET = TCP_hijack

REBUILDABLE = $(TARGET) *.o

all: $(TARGET)

$(TARGET): $(TARGET).o
	cc -g -o $@ $^ -lpcap

%.o: %.c
	cc -g -Wall -o $@ -c $^

clean:
	rm -f $(REBUILDABLE)