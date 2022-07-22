#!/bin/sh

init_etc () {
    (cd /opt/dionaea/ && cp -van template/etc .)
}

init_lib () {
    (cd /opt/dionaea/ && cp -van template/lib var/)
}

init_log () {
    (cd /opt/dionaea/ && cp -van template/log var/)
}

if [ "x$DIONAEA_FORCE_INIT" = "x1" ]; then
    echo "Forced to copy files ..."
    init_etc
    init_lib
    init_log
elif [ "x$DIONAEA_SKIP_INIT" = "x" ]; then
    test ! -d /opt/dionaea/etc/dionaea && init_etc
    test ! -d /opt/dionaea/var/lib/dionaea && init_lib
    test ! -d /opt/dionaea/var/log/dionaea && init_log
fi

if [ "x$DIONAEA_FORCE_INIT_CONF" = "x1" ]; then
    init_etc
fi

if [ "x$DIONAEA_FORCE_INIT_DATA" = "x1" ]; then
    init_lib
    init_log
fi

/opt/dionaea/bin/dionaea -D -u root -g root -c /opt/dionaea/etc/dionaea/dionaea.cfg
python3 sniff.py 
