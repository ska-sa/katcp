KATCP ?= ../katcp

include ../Makefile.inc

#CFLAGS := $(filter-out -DDEBUG,$(CFLAGS))

GITVER := $(shell git describe --always --tags --dirty 2> /dev/null || echo unknown)
CPPFLAGS+=-DV_GIT=\"$(GITVER)\"

INC = -I$(KATCP)
LIB = -L$(KATCP) -lkatcp

EXE = kcsdplxd
SRC = kcsdplx.c

OBJ = $(patsubst %.c,%.o,$(SRC))

all: $(EXE)

$(EXE): $(OBJ)
	$(CC) $(LDFLAGS) -o $@ $(OBJ) $(LIB)

%.o: %.c $(wildcard *.h)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< $(INC)

clean:
	$(RM) $(OBJ) core $(EXE)

install: all
	$(INSTALL) $(EXE) $(PREFIX)/sbin
