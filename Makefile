CC = gcc
CFLAGS = -lpcap -I/usr/include/pcap
LDFLAGS = -lpcap -lncurses -lm

SRCS = dhcp-stats.c
OBJS = $(SRCS:.c=.o)

all: dhcp-stats

dhcp-stats: $(OBJS)
	$(CC) $(CFLAGS) $(OBJS) -o $@ $(LDFLAGS)

%.o: %.c
	$(CC) -c $(CFLAGS) $< -o $@

clean:
	rm -f dhcp-stats $(OBJS)
