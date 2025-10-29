#!/bin/bash
# AUTHOR: aicdev (fivesec)

set -e 


# ==================== CONFIGURATION ====================
NETWORK_INTERFACE=eth0
SSH_PORT=22
SSH_BANN_TIME=180
SSH_MAX_ATTEMPTS=3
WEB_HTTP=80
WEB_TLS=443
PORTSCAN_BANN_TIME=360
BLOCK_CHAIN_LOG_PREFIX="IPTABLES_BLOCK_"

WEB_RATE_LIMIT="10/second"
WEB_BURST_LIMIT=20

# ==================== HELPER FUNCTIONS ====================
log_step() {
    echo "→ $1"
}

chain_exists() {
    iptables -L "$1" -n &>/dev/null
}

rule_exists() {
    iptables -C "$@" &>/dev/null 2>&1
}

# ==================== CREATE CUSTOM CHAINS ====================
create_chains() {
    log_step "Creating custom chains (if not exist)"
    
    if ! chain_exists BLOCK; then
        iptables -N BLOCK
        echo "created BLOCK chain"
    else
        echo "BLOCK chain already exists"
    fi
    
    if ! chain_exists LOG_DROP; then
        iptables -N LOG_DROP
        echo "created LOG_DROP chain"
    else
        echo "LOG_DROP chain already exists"
    fi
}

# ==================== CONFIGURE CHAINS ====================
configure_chains() {
    log_step "configuring custom chains"
    
    # BLOCK chain - logs and drops
    if ! rule_exists BLOCK -j LOG --log-prefix="${BLOCK_CHAIN_LOG_PREFIX}" --log-level 7; then
        iptables -A BLOCK -j LOG --log-prefix="${BLOCK_CHAIN_LOG_PREFIX}" --log-level 7
    fi
    if ! rule_exists BLOCK -j DROP; then
        iptables -A BLOCK -j DROP
    fi
    
    # LOG_DROP chain - logs and drops
    if ! rule_exists LOG_DROP -j LOG --log-prefix="IPTABLES_DROP_" --log-level 7; then
        iptables -A LOG_DROP -j LOG --log-prefix="IPTABLES_DROP_" --log-level 7
    fi
    if ! rule_exists LOG_DROP -j DROP; then
        iptables -A LOG_DROP -j DROP
    fi
}

# ==================== APPLY CORE RULES ====================
apply_core_rules() {
    log_step "allowing loopback traffic"
    if ! rule_exists INPUT -i lo -j ACCEPT; then
        iptables -A INPUT -i lo -j ACCEPT
    fi
    if ! rule_exists OUTPUT -o lo -j ACCEPT; then
        iptables -A OUTPUT -o lo -j ACCEPT
    fi
    
    log_step "allowing established and related connections"
    if ! rule_exists INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT; then
        iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    fi
    
    log_step "dropping invalid packets"
    if ! rule_exists INPUT -i $NETWORK_INTERFACE -m conntrack --ctstate INVALID -j DROP; then
        iptables -A INPUT -i $NETWORK_INTERFACE -m conntrack --ctstate INVALID -j DROP
    fi
}

# ==================== ANTI-SPOOFING ====================
apply_antispoofing() {
    log_step "applying anti-spoofing rules"
    
     # Drop packets with impossible source addresses
    if ! rule_exists INPUT -i $NETWORK_INTERFACE -s 127.0.0.0/8 -j DROP; then
        iptables -A INPUT -i $NETWORK_INTERFACE -s 127.0.0.0/8 -j DROP
    fi
    if ! rule_exists INPUT -i $NETWORK_INTERFACE -s 0.0.0.0/8 -j DROP; then
        iptables -A INPUT -i $NETWORK_INTERFACE -s 0.0.0.0/8 -j DROP
    fi
    if ! rule_exists INPUT -i $NETWORK_INTERFACE -s 169.254.0.0/16 -j DROP; then
        iptables -A INPUT -i $NETWORK_INTERFACE -s 169.254.0.0/16 -j DROP
    fi
    if ! rule_exists INPUT -i $NETWORK_INTERFACE -s 224.0.0.0/4 -j DROP; then
        iptables -A INPUT -i $NETWORK_INTERFACE -s 224.0.0.0/4 -j DROP
    fi
    if ! rule_exists INPUT -i $NETWORK_INTERFACE -s 240.0.0.0/5 -j DROP; then
        iptables -A INPUT -i $NETWORK_INTERFACE -s 240.0.0.0/5 -j DROP
    fi
}

# ==================== ICMP RULES ====================
apply_icmp_rules() {
    log_step "configuring ICMP rules"
    
    # Allow ping replies (type 0)
    if ! rule_exists INPUT -i $NETWORK_INTERFACE -p icmp --icmp-type 0 -j ACCEPT; then
        iptables -A INPUT -i $NETWORK_INTERFACE -p icmp --icmp-type 0 -j ACCEPT
    fi
    
    # Allow destination unreachable (type 3)
    if ! rule_exists INPUT -i $NETWORK_INTERFACE -p icmp --icmp-type 3 -j ACCEPT; then
        iptables -A INPUT -i $NETWORK_INTERFACE -p icmp --icmp-type 3 -j ACCEPT
    fi
    
    # Allow time exceeded (type 11)
    if ! rule_exists INPUT -i $NETWORK_INTERFACE -p icmp --icmp-type 11 -j ACCEPT; then
        iptables -A INPUT -i $NETWORK_INTERFACE -p icmp --icmp-type 11 -j ACCEPT
    fi
    
    # Rate-limit ping requests (type 8)
    if ! rule_exists INPUT -i $NETWORK_INTERFACE -p icmp --icmp-type 8 -m limit --limit 1/second --limit-burst 2 -j ACCEPT; then
        iptables -A INPUT -i $NETWORK_INTERFACE -p icmp --icmp-type 8 -m limit --limit 1/second --limit-burst 2 -j ACCEPT
    fi
    if ! rule_exists INPUT -i $NETWORK_INTERFACE -p icmp --icmp-type 8 -j DROP; then
        iptables -A INPUT -i $NETWORK_INTERFACE -p icmp --icmp-type 8 -j DROP
    fi
    
    # Drop ICMP attacks
    if ! rule_exists INPUT -i $NETWORK_INTERFACE -p icmp --icmp-type address-mask-request -j DROP; then
        iptables -A INPUT -i $NETWORK_INTERFACE -p icmp --icmp-type address-mask-request -j DROP
    fi
    if ! rule_exists INPUT -i $NETWORK_INTERFACE -p icmp --icmp-type timestamp-request -j DROP; then
        iptables -A INPUT -i $NETWORK_INTERFACE -p icmp --icmp-type timestamp-request -j DROP
    fi
    if ! rule_exists INPUT -i $NETWORK_INTERFACE -p icmp --icmp-type router-solicitation -j DROP; then
        iptables -A INPUT -i $NETWORK_INTERFACE -p icmp --icmp-type router-solicitation -j DROP
    fi
}

# ==================== SSH PROTECTION ====================
apply_ssh_protection() {
    log_step "applying SSH brute-force protection"
    
    if ! rule_exists INPUT -i $NETWORK_INTERFACE -p tcp --dport $SSH_PORT -m conntrack --ctstate NEW -m recent --set --name SSH; then
        iptables -A INPUT -i $NETWORK_INTERFACE -p tcp --dport $SSH_PORT -m conntrack --ctstate NEW -m recent --set --name SSH
    fi
    
    if ! rule_exists INPUT -i $NETWORK_INTERFACE -p tcp --dport $SSH_PORT -m conntrack --ctstate NEW -m recent --update --seconds $SSH_BANN_TIME --hitcount $SSH_MAX_ATTEMPTS --name SSH --rsource -j BLOCK; then
        iptables -A INPUT -i $NETWORK_INTERFACE -p tcp --dport $SSH_PORT -m conntrack --ctstate NEW -m recent --update --seconds $SSH_BANN_TIME --hitcount $SSH_MAX_ATTEMPTS --name SSH --rsource -j BLOCK
    fi
    
    if ! rule_exists INPUT -i $NETWORK_INTERFACE -p tcp --dport $SSH_PORT -m conntrack --ctstate NEW -j ACCEPT; then
        iptables -A INPUT -i $NETWORK_INTERFACE -p tcp --dport $SSH_PORT -m conntrack --ctstate NEW -j ACCEPT
    fi
}

# ==================== WEB SERVER PROTECTION ====================
apply_web_protection() {
    log_step "applying web server protection with rate limiting"
    
    # HTTP rate limiting
    if ! rule_exists INPUT -i $NETWORK_INTERFACE -p tcp --dport $WEB_HTTP -m conntrack --ctstate NEW -m limit --limit $WEB_RATE_LIMIT --limit-burst $WEB_BURST_LIMIT -j ACCEPT; then
        iptables -A INPUT -i $NETWORK_INTERFACE -p tcp --dport $WEB_HTTP -m conntrack --ctstate NEW -m limit --limit $WEB_RATE_LIMIT --limit-burst $WEB_BURST_LIMIT -j ACCEPT
    fi
    if ! rule_exists INPUT -i $NETWORK_INTERFACE -p tcp --dport $WEB_HTTP -m conntrack --ctstate NEW -j LOG_DROP; then
        iptables -A INPUT -i $NETWORK_INTERFACE -p tcp --dport $WEB_HTTP -m conntrack --ctstate NEW -j LOG_DROP
    fi
    
    # HTTPS rate limiting
    if ! rule_exists INPUT -i $NETWORK_INTERFACE -p tcp --dport $WEB_TLS -m conntrack --ctstate NEW -m limit --limit $WEB_RATE_LIMIT --limit-burst $WEB_BURST_LIMIT -j ACCEPT; then
        iptables -A INPUT -i $NETWORK_INTERFACE -p tcp --dport $WEB_TLS -m conntrack --ctstate NEW -m limit --limit $WEB_RATE_LIMIT --limit-burst $WEB_BURST_LIMIT -j ACCEPT
    fi
    if ! rule_exists INPUT -i $NETWORK_INTERFACE -p tcp --dport $WEB_TLS -m conntrack --ctstate NEW -j LOG_DROP; then
        iptables -A INPUT -i $NETWORK_INTERFACE -p tcp --dport $WEB_TLS -m conntrack --ctstate NEW -j LOG_DROP
    fi
}

# ==================== PORT SCAN DETECTION ====================
apply_portscan_detection() {
    log_step "applying port scan detection"
    
    # Detect port scanning (connections to closed ports)
    if ! rule_exists INPUT -i $NETWORK_INTERFACE -p tcp -m multiport ! --dports $SSH_PORT,$WEB_HTTP,$WEB_TLS -m recent --name PORTSCAN --set -j LOG_DROP; then
        iptables -A INPUT -i $NETWORK_INTERFACE -p tcp -m multiport ! --dports $SSH_PORT,$WEB_HTTP,$WEB_TLS -m recent --name PORTSCAN --set -j LOG_DROP
    fi
    
    # Block further traffic from port scanners
    if ! rule_exists INPUT -i $NETWORK_INTERFACE -m recent --name PORTSCAN --rcheck --seconds $PORTSCAN_BANN_TIME -j BLOCK; then
        iptables -A INPUT -i $NETWORK_INTERFACE -m recent --name PORTSCAN --rcheck --seconds $PORTSCAN_BANN_TIME -j BLOCK
    fi
}

# ==================== SYN FLOOD PROTECTION ====================
apply_synflood_protection() {
    log_step "applying SYN flood protection"
    
    if ! rule_exists INPUT -i $NETWORK_INTERFACE -p tcp --syn -m limit --limit 1/second --limit-burst 3 -j ACCEPT; then
        iptables -A INPUT -i $NETWORK_INTERFACE -p tcp --syn -m limit --limit 1/second --limit-burst 3 -j ACCEPT
    fi
    if ! rule_exists INPUT -i $NETWORK_INTERFACE -p tcp --syn -j DROP; then
        iptables -A INPUT -i $NETWORK_INTERFACE -p tcp --syn -j DROP
    fi
}

# ==================== DROP COMMON ATTACKS ====================
apply_attack_protection() {
    log_step "applying protection against common attacks"
    
    # Drop NULL packets
    if ! rule_exists INPUT -i $NETWORK_INTERFACE -p tcp --tcp-flags ALL NONE -j DROP; then
        iptables -A INPUT -i $NETWORK_INTERFACE -p tcp --tcp-flags ALL NONE -j DROP
    fi
    
    # Drop XMAS packets
    if ! rule_exists INPUT -i $NETWORK_INTERFACE -p tcp --tcp-flags ALL ALL -j DROP; then
        iptables -A INPUT -i $NETWORK_INTERFACE -p tcp --tcp-flags ALL ALL -j DROP
    fi
    
    # Drop packets with FIN flag without ACK
    if ! rule_exists INPUT -i $NETWORK_INTERFACE -p tcp --tcp-flags FIN,ACK FIN -j DROP; then
        iptables -A INPUT -i $NETWORK_INTERFACE -p tcp --tcp-flags FIN,ACK FIN -j DROP
    fi
    
    # Drop packets with SYN and FIN set
    if ! rule_exists INPUT -i $NETWORK_INTERFACE -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP; then
        iptables -A INPUT -i $NETWORK_INTERFACE -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP
    fi
}

# ==================== SHOW CONFIGURATION ====================
show_config() {
    echo -e "\n current iptables configuration:\n"
    iptables -L -v -n --line-numbers
    
    echo -e "\n custom chains:\n"
    if chain_exists BLOCK; then
        iptables -L BLOCK -v -n
    fi
    if chain_exists LOG_DROP; then
        iptables -L LOG_DROP -v -n
    fi
}

# ==================== SAVE RULES ====================
save_rules() {
    log_step "saving rules"
    
    if command -v iptables-save &> /dev/null; then
        mkdir -p /etc/iptables
        iptables-save > /etc/iptables/rules.v4
        echo "rules saved to /etc/iptables/rules.v4"
    else
        echo "iptables-persistent not installed. Rules will be lost on reboot."
        echo "you may want to install with: apt install iptables-persistent"
    fi
}

# ==================== MAIN  ====================
main() {
    if [[ $EUID -ne 0 ]]; then
        echo "this script must be run as root"
        exit 1
    fi
    
    echo "existing rules will be preserved"
    echo "only missing rules will be added"
    echo ""
    
    create_chains
    configure_chains
    apply_core_rules
    apply_antispoofing
    apply_icmp_rules
    apply_synflood_protection
    apply_attack_protection
    apply_ssh_protection
    apply_web_protection
    apply_portscan_detection
    
    show_config
    save_rules
    
    echo -e "\n firewall configuration complete! \n"
}

main
