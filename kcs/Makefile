KATCP ?= ../katcp

include ../Makefile.inc

INC = -I$(KATCP)
LIB = -L$(KATCP) -lkatcp -ldl

CFLAGS += -fPIC

BUILD = $(shell date -u +%Y-%m-%dT%H:%M:%S)
VERSION = $(GITVER)

CFLAGS += -DVERSION=\"$(VERSION)\"
CFLAGS += -DBUILD=\"$(BUILD)\"

SERVER = kcs
SRCSHARED = shared.c
SRC = $(SRCSHARED) watchannounce.c subprocess.c actor.c statemachine.c statemachine_base.c roachpool.c execpy.c parser.c kcserver.c basic.c

OBJ = $(patsubst %.c,%.o,$(SRC))
all: $(SERVER)

#$(SERVER): $(OBJ) 
$(SERVER): $(OBJ) $(KATCP)/libkatcp.a
	$(CC) -o $@ $(OBJ) $(LIB)

clean: 
	$(RM) -f $(SERVER) *.o test-*

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@ $(INC)

install: all
	$(INSTALL) $(SERVER) $(PREFIX)/sbin

test-parser: parser.c 
	$(CC) $(CFLAGS) -DSTANDALONE -o $@ $^ -I../katcp

test-execpy: execpy.c 
	$(CC) $(CFLAGS) -DSTANDALONE -o $@ $^ -I../katcp -L../katcp -lkatcp

test-roachpool: $(SRCSHARED) roachpool.c 
	$(CC) $(CFLAGS) -DSTANDALONE -o $@ $^ -I../katcp
  
test-kurl: $(SRCSHARED) kurl.c 
	$(CC) $(CFLAGS) -DSTANDALONE -o $@ $^ -I../katcp

test-statemachine: statemachine.c 
	$(CC) $(CFLAGS) -DSTANDALONE -o $@ $^ -I../katcp

test-avltree: avltree.c 
	$(CC) $(CFLAGS) -DSTANDALONE -o $@ $^

test-type: ktype.c 
	$(CC) $(CFLAGS) -DSTANDALONE -o $@ $^ $(INC) $(LIB)

test-actor: actor.c statemachine.c
	$(CC) $(CFLAGS) -D__ACTOR_UNIT_TEST -o $@ $^ $(INC) $(LIB)

