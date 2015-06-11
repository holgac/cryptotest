CC=gcc

DEBUG=true
INCLUDEDIR=./include
SRCDIR=./
CFLAGS=-c -I$(INCLUDEDIR) -Wall -std=gnu90
OPT=-Wall
SOURCES=$(shell find $(SRCDIR) -name "*.c")
OBJECTS=$(SOURCES:%.c=%.o)
	TARGET=rypto

ifeq ($(DEBUG),true)
	CFLAGS+=-g
endif

$(TARGET): $(OBJECTS)
			$(CC) $^ -o $@

clean:
		rm -f $(TARGET) $(OBJECTS)
