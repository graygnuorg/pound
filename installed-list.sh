#!/bin/sh
# List installed Pound files.

SYSTEMD="false"

if [ "${SYSTEMD}" = "true" ]; then
    # SystemD daemon
    ls -l /etc/systemd/system/pound.service
else
    # SystemV daemon
    ls -l /etc/default/pound
    ls -l /etc/init.d/pound
    ls -l /etc/rc?.d/*pound
fi

POUND_PATH="/usr/local"

ls -l /etc/pound/*.cfg
ls -l /etc/pound/*.html
ls -l /etc/pound/ca/
ls -l /etc/pound/cert/
ls -l /etc/rsyslog.d/30-pound.conf
ls -l ${POUND_PATH}/share/doc/pound/*
ls -l ${POUND_PATH}/share/man/man8/pound.8*
ls -l ${POUND_PATH}/share/man/man8/poundctl.8*
ls -l ${POUND_PATH}/*bin/poundctl
ls -l ${POUND_PATH}/sbin/pound
ls -l /var/chroot/pound/
ls -l /var/log/pound/
ls -l /var/run/pound/poundctl.socket

ls -l /var/lib/dpkg/info/pound*
