#/bin/bash
# AUTHOR: aicdev
# LINK:   https://securityvalley.org
# REPO:   github.com/aicdev/annoy-the-script-kiddie
# ABOUT:  simple linux netfilter rules to annoy some bots and script-kiddies in the wild. rules are gonna set with iptables
# you can install iptables by running: apt install iptables
# IMPORTANT: if you restart your machine, all iptable rules are gone. to save them you can install iptables-persistent, simply run:
# apt install iptables-persistent

echo -e "\n\nCONFIGURE IPTABLES TO ANNOY THE SCRIPT-KIDDIE\n\n"

# PLEASE CHANGE THIS TO THE NETWORK INTERFACE YOU WANNA PROTECT
# netstat -tupln
# ip a s
NETWORK_INTERFACE=eth0

# sometimes a good idea to move the default ssh port
# just edit /etc/ssh/sshd_config and change port from 22 to f.g. 22223
# most of the scan bots gonna fail
SSH_PORT=22

# if we detect ssh bruteforce attempt, we block all further traffic for 3 min
SSH_BANN_TIME=180

# custom for my web server (nginx) deployment
WEB_HTTP=80
WEB_TLS=443

# if we detect a possible scan, we block all further traffic for 6 min
PORTSCAN_BANN_TIME=360

# prefix inside the iptables log
# for journalctl you can run the following:
# journalctl -k -f -g IPTABLES_BLOCK_
BLOCK_CHAIN_LOG_PREFIX="IPTABLES_BLOCK_"

create_chains()
{
  echo "create BLOCK chain"
  iptables -N BLOCK
}

apply_rules()
{
  echo "add rules"
  echo "add log "
  iptables -I BLOCK -j LOG --log-prefix="${BLOCK_CHAIN_LOG_PREFIX}" --log-level 7
  iptables -A BLOCK -j DROP

  # DROP INVALID PACKETS
  echo "add rule to drop invalid packets"
  iptables -i $NETWORK_INTERFACE -I INPUT -m state --state INVALID -j DROP

  # DROP ICMP SMURF ATTACK (https://en.wikipedia.org/wiki/Smurf_attack)
  echo "add rule to drop ICMP SMURF ATTACKS"
  iptables -i $NETWORK_INTERFACE -A INPUT -p icmp -m icmp --icmp-type address-mask-request -j DROP
  iptables -i $NETWORK_INTERFACE -A INPUT -p icmp -m icmp --icmp-type timestamp-request -j DROP

  # ALLOW OUTGOING TRAFFIC
  echo "allow outgoing traffic"
  iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

  # PROTECT SSH PORT
  echo "add rule to protect ssh port"
  iptables -i $NETWORK_INTERFACE -A INPUT -p tcp --dport $SSH_PORT -m state --state NEW -m recent --set --name SSH
  iptables -i $NETWORK_INTERFACE -A INPUT -p tcp --dport $SSH_PORT -m state --state NEW -m recent --update --seconds $SSH_BANN_TIME --hitcount 3 --name SSH --rsource -j BLOCK

  # RESTRICT POSSIBLE NOISY PORTSCANS
  echo "add rule to annoy the port-scanner"
  iptables -i $NETWORK_INTERFACE -A INPUT -p tcp -m tcp -m multiport ! --dports $SSH_PORT,$WEB_HTTP,$WEB_TLS -m recent --name PORTSCAN --set
  iptables -i $NETWORK_INTERFACE -A INPUT -m recent --name PORTSCAN --rcheck --seconds $PORTSCAN_BANN_TIME -j BLOCK

  # ALLOW SSH ACCESS
  echo "allow ssh access"
  iptables -i $NETWORK_INTERFACE -A INPUT -p tcp --dport $SSH_PORT -j ACCEPT

  # ALLOW WEBSERVER ACCESS
  echo "allow webserver access"
  iptables -i $NETWORK_INTERFACE -A INPUT -p tcp -m multiport --dports $WEB_HTTP,$WEB_TLS -j ACCEPT

  # ALLOW TRAFFIC ON LOOPBACK INTERFACE
  echo "allow loopback traffic"
  iptables -I INPUT -i lo -j ACCEPT

  # DROP THE REST
  echo "drop all the other traffic"
  iptables -A INPUT -j DROP
}

block_icmp_ping()
{
  iptables -i $NETWORK_INTERFACE -I INPUT -p icmp -m icmp --icmp-type 8 -j DROP
}

show_config()
{
  iptables -L -v --line-numbers
}

create_chains
apply_rules

# just comment that line if you wanna allow icmp ping packets
block_icmp_ping

show_config
