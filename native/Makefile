CC = gcc
HARDEN_CFLAGS = -O2 -g -Wall -Wextra -Werror -fstack-protector-strong -D_FORTIFY_SOURCE=2 -fPIE
HARDEN_LDFLAGS = -Wl,-z,relro,-z,now -Wl,-z,noexecstack

all: libmetaparse.so poc_fixed poc_asan_fixed

libmetaparse.so: metaparse.c
	$(CC) $(HARDEN_CFLAGS) -shared -fPIC metaparse.c -o libmetaparse.so $(HARDEN_LDFLAGS)

poc_fixed: metaparse.c
	$(CC) $(HARDEN_CFLAGS) -pie -DSTANDALONE_POC metaparse.c -o poc_fixed $(HARDEN_LDFLAGS)

poc_asan_fixed: metaparse.c
	$(CC) -O1 -g -fsanitize=address -DSTANDALONE_POC metaparse.c -o poc_asan_fixed

clean:
	rm -f libmetaparse.so poc_fixed poc_asan_fixed poc_vuln poc_asan
