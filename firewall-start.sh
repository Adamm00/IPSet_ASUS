#!/bin/sh

cru a Firewall_save "0 * * * * /jffs/scripts/firewall save"
sh /jffs/scripts/firewall start
