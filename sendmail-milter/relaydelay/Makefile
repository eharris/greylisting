SENDMAIL=/export/home/murf/sendmail-8.12.9
VERSION = 0.6
unam = $(strip ${shell /bin/uname})

ifeq ($(unam),SunOS)
os = $(strip ${shell /bin/uname -r})

ifeq ($(os),5.5.1)
LIBS=-L/usr/local/mysql/lib/mysql  -lmilter -lsm -lmysqlclient_r  -lpthread -lm -lz -lresolv -lsocket -lnsl
INCL=-I/usr/local/mysql/include/mysql

else
LIBS=-L/usr/local/lib/mysql  -lmilter -lmysqlclient_r  -lpthread -lm -lz -lresolv -lsocket -lnsl
INCL=-I/usr/local/include/mysql

endif


endif

ifeq ($(unam),Linux)
LIBS=-L/usr/lib/mysql -L/usr/lib/libmilter -lmilter -lmysqlclient_r  -lpthread -lm -lresolv -lnsl
INCL=-I/usr/include/mysql
endif


relaydelay : relaydelay.o config_gram.o config_lex.o
	gcc -g -o relaydelay relaydelay.o config_gram.o config_lex.o $(LIBS)

relaydelay.o : relaydelay.c
	gcc -c -g $(INCL) relaydelay.c -DVERSION=\"$(VERSION)\"

config_gram.o : config_gram.tab.c
	gcc -c -g config_gram.tab.c -o config_gram.o

config_lex.o : config_lex.c
	gcc -c -g config_lex.c

config_gram.tab.c config_gram.tab.h : config_gram.y
	bison -p relaydelay_ -vd config_gram.y

config_lex.c : config_lex.l config_gram.tab.h
	flex -Prelaydelay_ config_lex.l
	mv lex.relaydelay_.c config_lex.c

tar :
	(cd ..; tar czvf relaydelay_c-$(VERSION).tar.gz relaydelay-$(VERSION)/Makefile relaydelay-$(VERSION)/relaydelay.c \
	relaydelay-$(VERSION)/config_lex.l \
	relaydelay-$(VERSION)/config_gram.y \
	relaydelay-$(VERSION)/relaydelay.conf \
	)
clean:
	rm -f relaydelay relaydelay.o config_gram.o config_gram.tab.c config_gram.tab.h config_lex.c config_lex.o config_gram.output


