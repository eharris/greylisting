SENDMAIL=/export/home/murf/sendmail-8.12.9
VERSION = 0.2
unam = $(strip ${shell /bin/uname})

ifeq ($(unam),SunOS)
LIBS=-L/usr/local/lib/mysql  -lmilter -lmysqlclient_r  -lpthread -lm -lz -lresolv -lsocket -lnsl
INCL=-I/usr/local/include/mysql
endif

ifeq ($(unam),Linux)
LIBS=-L/usr/lib/mysql  -lmilter -lmysqlclient_r  -lpthread -lm -lresolv -lnsl
INCL=-I/usr/include/mysql
endif


relaydelay : relaydelay.o
	gcc -g -o relaydelay relaydelay.o $(LIBS)

relaydelay.o : relaydelay.c
	gcc -c -g $(INCL) relaydelay.c -DVERSION=\"$(VERSION)\"

tar :
	(cd ..; tar czvf relaydelay_c-$(VERSION).tar.gz relaydelay-$(VERSION)/Makefile relaydelay-$(VERSION)/relaydelay.c)
clean:
	rm -f relaydelay relaydelay.o
