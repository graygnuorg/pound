#!/bin/sh
sudo /usr/local/sbin/pound -f /etc/pound/pound.cfg -p pound.pid
sudo /usr/local/bin/poundctl -c '/var/run/pound/poundctl.socket'
echo "To stop pound use: sudo kill $(sudo cat pound.pid)"
