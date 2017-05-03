#!/bin/sh

echo "0 * * * * /jffs/scripts/firewall save" > /var/spool/cron/crontabs/`nvram get http_username`
[ -n "`pidof crond`" ] && killall -q crond

sleep 5
crond
sh /jffs/scripts/firewall