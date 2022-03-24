#!/bin/bash
# iptables preflight configuration
# Sources:
# - https://rhau.se/2009/02/10/simple-iptables-firewall-script-with-nat-and-sfq-sceduling/
# - https://docs.mitmproxy.org/stable/howto-transparent/

#Setting up some Variables #####################################################
EXTIP=$(ifconfig | grep -b1 "eth0" | grep -i inet | cut -d":" -f2 | cut -d" " -f1) # Example 1.2.3.4
INTIP=10.0.1.1                                                                     # Example 192.168.1.1
INTNET=10.0.1.1/24                                                                 # Example 192.168.1.0/24
EXTIF=eth0                                                                         # Example eth0
INTIF=eth1                                                                         # Example eth1

#Disabling ipforwarding aka routing ############################################
echo 0 > /proc/sys/net/ipv4/ip_forward

#Flushing tables and setting policys ###########################################
iptables -F
iptables -t nat -F PREROUTING
iptables -t nat -F POSTROUTING
iptables -t mangle -F
iptables -P FORWARD DROP
iptables -P INPUT DROP
iptables -P OUTPUT ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT
iptables -A INPUT -i lo -j ACCEPT

# INPUT from local network #####################################################
iptables -A INPUT -i $INTIF -s $INTNET -j ACCEPT
iptables -A INPUT -i $INTIF -p udp --dport 67 --sport 68 -j ACCEPT

# Dropping private addresses on the external interface ########################
iptables -A INPUT -i $EXTIF -s 10.0.0.0/8 -j DROP
iptables -A INPUT -i $EXTIF -s 172.16.0.0/12 -j DROP
iptables -A INPUT -i $EXTIF -s 192.168.0.0/16 -j DROP
iptables -A INPUT -i $EXTIF -s 169.254.0.0/16 -j DROP
iptables -A INPUT -i ! lo -s 127.0.0.0/8 -j DROP

# INPUT from external networks #################################################
iptables -A INPUT -d $EXTIP -p tcp --dport 22 --sport 1024:65535 -j ACCEPT # SSH

# DMZ
iptables -t nat -A PREROUTING -i $EXTIF -j DNAT --to 10.0.1.100
iptables -A FORWARD -d 10.0.1.100 -j ACCEPT

# ICMP from external networks ##################################################
iptables -A INPUT -i $EXTIF -d $EXTIP -p icmp --icmp-type \
  destination-unreachable -j ACCEPT
iptables -A INPUT -i $EXTIF -d $EXTIP -p icmp --icmp-type \
  source-quench -j ACCEPT
iptables -A INPUT -i $EXTIF -d $EXTIP -p icmp --icmp-type \
  time-exceeded -j ACCEPT
iptables -A INPUT -i $EXTIF -d $EXTIP -p icmp --icmp-type \
  parameter-problem -j ACCEPT
iptables -A INPUT -i $EXTIF -d $EXTIP -p icmp --icmp-type \
  echo-request -m limit --limit 2/second --limit-burst 5 -j ACCEPT

# Allowing all traffic that is related to our traffic :) aka STATEFUL ##########
iptables -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT

# FORWARD between internal and external network ################################
iptables -A FORWARD -i $INTIF -o $EXTIF -s $INTNET -d ! $INTNET -j ACCEPT
iptables -A FORWARD -i $EXTIF -s ! $INTNET -d $INTNET \
  -m state --state RELATED,ESTABLISHED -j ACCEPT

# MASQUERADING aka NAT #########################################################
iptables -t nat -A POSTROUTING -o $EXTIF -s $INTNET -d ! $INTNET -j MASQUERADE

# NAT rules for DNS redirection ################################################
# Note, this cannot catch DNS-over-HTTPS, but we can catch that with mitmproxy
iptables -t nat -A OUTPUT -p udp --dport 53 -j DNAT --to $INTIP:53
iptables -t nat -A OUTPUT -p tcp --dport 53 -j DNAT --to $INTIP:53

# Redirect HTTP(S) traffic to mitmproxy ########################################
iptables -t nat -A PREROUTING -i $INTIF -p tcp --dport 80 -j REDIRECT --to-port 8080
iptables -t nat -A PREROUTING -i $INTIF -p tcp --dport 443 -j REDIRECT --to-port 8080
ip6tables -t nat -A PREROUTING -i $INTIF -p tcp --dport 80 -j REDIRECT --to-port 8080
ip6tables -t nat -A PREROUTING -i $INTIF -p tcp --dport 443 -j REDIRECT --to-port 8080

# Enabling stuff in /proc ######################################################
echo 1 > /proc/sys/net/ipv4/tcp_syncookies
echo 1 > /proc/sys/net/ipv4/icmp_echo_ignore_broadcasts
echo 1 > /proc/sys/net/ipv4/icmp_ignore_bogus_error_responses
echo 1 > /proc/sys/net/ipv4/conf/$EXTIF/log_martians
echo 0 > /proc/sys/net/ipv4/conf/$EXTIF/accept_redirects
echo 0 > /proc/sys/net/ipv4/conf/$EXTIF/accept_source_route
sysctl -w net.ipv4.ip_forward=1
sysctl -w net.ipv6.conf.all.forwarding=1
sysctl -w net.ipv4.conf.all.send_redirects=0

# Enabling anti Spoofing #######################################################
if [ -e /proc/sys/net/ipv4/conf/all/rp_filter ]; then
  for f in /proc/sys/net/ipv4/conf/*/rp_filter; do
    echo 1 > $f
  done
else
  echo
  echo "PROBLEMS SETTING UP IP SPOOFING PROTECTION.  BE WORRIED."
  echo
fi

# Full transparent proxy #######################################################
TABLE_ID=100
MARK=1

echo "$TABLE_ID     mitmproxy" >> /etc/iproute2/rt_tables
iptables -t mangle -A PREROUTING -d $INTNET -j MARK --set-mark $MARK
iptables -t nat \
  -A PREROUTING -p tcp -s $INTNET \
  --match multiport --dports 80,443 -j \
  REDIRECT --to-port 8080

ip rule add fwmark $MARK lookup $TABLE_ID
ip route add local $INTNET dev lo table $TABLE_ID

# Enabling ipforwarding aka routing ############################################
echo 1 > /proc/sys/net/ipv4/ip_forward

# Enabling Stochastic Fairness Queuing #########################################
tc qdisc add dev $EXTIF root sfq perturb 10

# Lsting rules ################################################################
iptables -L -n -v
iptables -t nat -L -n -v
