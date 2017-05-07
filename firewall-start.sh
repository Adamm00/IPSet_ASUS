#!/bin/sh

	if [ X"`ps | grep firewall-start | wc -l`" != X"3" ]
	then
		exit # firewall-start fix
	else
		sleep 10
		cru a Firewall_save "0 * * * * /jffs/scripts/firewall save"
		sh /jffs/scripts/firewall start
	fi
