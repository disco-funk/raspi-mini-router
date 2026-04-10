#!/usr/bin/env bash
set -e

# Interfaces
WAN_IF="usb0"
LAN_IF="eth0"

# LAN config
LAN_IP="192.168.0.1"
LAN_NET="192.168.0.0/24"

# Toggle: restrict outbound traffic (0 = allow all, 1 = restrict)
EGRESS_RESTRICT=0

NFT_CONF="/etc/nftables.conf"

echo "[+] Configuring LAN interface..."
ip addr flush dev "$LAN_IF"
ip addr add "$LAN_IP/24" dev "$LAN_IF"
ip link set "$LAN_IF" up

echo "[+] Enabling IPv4 forwarding..."
sysctl -w net.ipv4.ip_forward=1 > /dev/null

echo "[+] Disabling IPv6..."
sysctl -w net.ipv6.conf.all.disable_ipv6=1 > /dev/null
sysctl -w net.ipv6.conf.default.disable_ipv6=1 > /dev/null

echo "[+] Writing nftables config..."

cat > "$NFT_CONF" <<EOF
flush ruleset

########################
# FILTER TABLE
########################
table inet filter {

    #
    # INPUT: traffic to the Pi itself
    #
    chain input {
        type filter hook input priority 0;
        policy drop;

        # Drop garbage early
        ct state invalid drop

        # Allow loopback
        iif lo accept

        # Allow established/related
        ct state established,related accept

        # Allow ICMP (rate-limited)
        ip protocol icmp limit rate 5/second accept

        # Allow SSH from LAN only (rate-limited)
        iif "$LAN_IF" tcp dport 22 ct state new limit rate 10/minute accept
    }

    #
    # FORWARD: traffic passing through
    #
    chain forward {
        type filter hook forward priority 0;
        policy drop;

        # Drop invalid early
        ct state invalid drop

        # Anti-spoofing: only allow LAN subnet from LAN interface
        iif "$LAN_IF" ip saddr != $LAN_NET drop

        # LAN -> WAN (optionally restricted)
        iif "$LAN_IF" oif "$WAN_IF" ct state new,established,related ${
            EGRESS_RESTRICT:+ip protocol { tcp, udp, icmp } accept
        }
        ${EGRESS_RESTRICT:+
        # Example: only allow HTTP/HTTPS/DNS if restricted
        iif "$LAN_IF" oif "$WAN_IF" tcp dport {80,443} accept
        iif "$LAN_IF" oif "$WAN_IF" udp dport 53 accept
        iif "$LAN_IF" oif "$WAN_IF" ip protocol icmp accept
        }

        # Allow return traffic
        iif "$WAN_IF" oif "$LAN_IF" ct state established,related accept
    }
}

########################
# NAT TABLE
########################
table ip nat {
    chain postrouting {
        type nat hook postrouting priority 100;
        oif "$WAN_IF" masquerade
    }
}
EOF

echo "[+] Applying nftables rules..."
nft -f "$NFT_CONF"

echo "[+] Enabling nftables service..."
systemctl enable nftables >/dev/null 2>&1 || true
systemctl restart nftables

echo "[+] Done."