#!/bin/sh
#

CONFIG=/etc/mail/relaydelay.conf

case "$1" in
    start)
        /usr/local/sbin/relaydelay.pl $CONFIG
        ;;

    stop)
        kill `cat /var/run/relaydelay.pid`
        ;;

    *)
        echo ""
        echo "Usage: `basename $0` { start | stop }"
        echo ""
        ;;
esac

