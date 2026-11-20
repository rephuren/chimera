CC ?= cc
CFLAGS ?= -std=c11 -O2 -g -Wall -Wextra -Wshadow -Wconversion -Wno-sign-conversion
SAN = -fsanitize=address,undefined -fno-omit-frame-pointer
INC = -Iinclude -Ibuild
SRC = src/pcap.c src/decode.c src/dns.c src/tls.c src/store.c src/ingest.c
LIBS = -lsqlite3

.PHONY: all test clean
all: build/chimera-core

build/schema_sql.h: ../sql/schema.sql
	@mkdir -p build
	awk 'BEGIN{print "static const char SCHEMA[] ="} {gsub(/\\/,"\\\\"); gsub(/"/,"\\\""); print "\"" $$0 "\\n\""} END{print ";"}' $< > $@

build/chimera-core: $(SRC) src/main.c include/chimera.h build/schema_sql.h
	$(CC) $(CFLAGS) $(INC) $(SRC) src/main.c -o $@ $(LIBS)

build/test: $(SRC) tests/test_main.c include/chimera.h build/schema_sql.h
	$(CC) $(CFLAGS) $(SAN) $(INC) $(SRC) tests/test_main.c -o $@ $(LIBS)

test: build/test
	./build/test

clean:
	rm -rf build
