#!/bin/bash
#
# WireGuard Key Generator with Walkthrough
# A user-friendly tool for generating WireGuard keys and configurations
# Version 1.2
#

set -eo pipefail
trap 'echo -e "\n\033[1;31m[ERROR] Script failed at line $LINENO\033[0m"; exit 1' ERR

# Configuration
VERSION="1.2"
DEFAULT_PORT=51820
DEFAULT_SERVER_IP="10.0.0.1/24"
DEFAULT_CLIENT_NETWORK="10.0.0"
DEFAULT_DNS="1.1.1.1,1.0.0.1"
CONFIG_DIR=""
CLIENTS=()
CLIENT_TYPES=()
CLIENT_NETWORKS=()
CLIENT_DESCRIPTIONS=()

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
PURPLE='\033[0;35m'
NC='\033[0m' # No Color
BOLD='\033[1m'

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Please run as root (sudo)${NC}"
    exit 1
fi

# Logging functions
log_info()  { echo -e "${GREEN}[INFO]  $*${NC}"; }
log_warn()  { echo -e "${YELLOW}[WARN]  $*${NC}"; }
log_error() { echo -e "${RED}[ERROR] $*${NC}"; }
log_step()  { echo -e "\n${BOLD}${BLUE}[STEP $1]${NC} ${BOLD}$2${NC}"; }
log_prompt() { echo -e "${BLUE}[INPUT] $*${NC}"; }

# Utility functions
prompt_yes_no() {
    local prompt="$1"
    local default="${2:-y}"
    while true; do
        log_prompt "$prompt [Y/n]: "
        read -r response
        response=${response:-$default}
        case "$response" in
            [Yy]* ) return 0;;
            [Nn]* ) return 1;;
            * ) log_error "Please answer yes or no.";;
        esac
    done
}

# Display functions
display_header() {
    printf "\033c" # Clear screen
    echo -e "${BLUE}${BOLD}===============================================${NC}"
    echo -e "${BLUE}${BOLD}    WireGuard Key Generator v${VERSION}    ${NC}"
    echo -e "${BLUE}${BOLD}===============================================${NC}"
    echo
}

display_footer() {
    echo
    echo -e "${BOLD}Press Enter to continue...${NC}"
    read -r
}

# Function to find the next available folder number
find_next_folder() {
    local i=0
    # Check both current directory and /etc/wireguard
    while [ -d "wg${i}" ] || [ -d "/etc/wireguard/wg${i}" ]; do
        i=$((i+1))
    done
    echo $i
}

# Check if WireGuard is installed
check_wireguard() {
    display_header
    log_info "Checking if WireGuard is installed..."

    if ! command -v wg &> /dev/null; then
        log_error "WireGuard is not installed"
        log_warn "Please install WireGuard before using this tool"
        echo -e "${YELLOW}You can usually install it with:${NC}"
        echo -e "${CYAN}  apt update && apt install -y wireguard-tools${NC}"
        exit 1
    fi

    # Check for qrencode
    if ! command -v qrencode &> /dev/null; then
        log_warn "qrencode is not installed - QR code generation will be disabled"
        echo -e "${YELLOW}You can install it with:${NC}"
        echo -e "${CYAN}  apt install -y qrencode${NC}"
        echo
    fi

    # Check for WireGuard service
    if ! systemctl list-unit-files | grep -q wg-quick; then
        log_warn "WireGuard systemd service not found - you may need to install wireguard package"
        echo -e "${YELLOW}For Debian/Ubuntu:${NC}"
        echo -e "${CYAN}  apt install -y wireguard${NC}"
    fi

    log_info "WireGuard is installed, continuing..."
}

# Select configuration directory
select_config_dir() {
    display_header
    log_step "1" "Selecting Configuration Directory"

    # Get next folder number
    folder_num=$(find_next_folder)
    folder_name="wg${folder_num}"

    echo -e "${CYAN}A separate directory will be created for your WireGuard configuration.${NC}"
    echo -e "${CYAN}This keeps keys, configs, and certificates organized.${NC}\n"

    echo -e "Where would you like to store the configuration?"
    echo -e "1) Current directory ($(pwd)/$folder_name)"
    echo -e "2) System directory (/etc/wireguard/$folder_name)"

    local storage_choice
    read -rp "Enter your choice [1-2]: " storage_choice

    case $storage_choice in
        2)
            # Check if /etc/wireguard exists
            if [ ! -d "/etc/wireguard" ]; then
                log_info "Creating /etc/wireguard directory..."
                mkdir -p "/etc/wireguard"
            fi

            CONFIG_DIR="/etc/wireguard/$folder_name"
            ;;
        *)
            CONFIG_DIR="$(pwd)/$folder_name"
            ;;
    esac

    log_info "Creating configuration in folder: ${BOLD}${CONFIG_DIR}${NC}"

    mkdir -p "$CONFIG_DIR"
    cd "$CONFIG_DIR" || {
        log_error "Failed to create and change to directory $CONFIG_DIR"
        exit 1
    }

    display_footer
}

# Collect basic information
collect_basic_info() {
    display_header
    log_step "2" "Basic Configuration"

    echo -e "${CYAN}Let's set up the basic WireGuard server configuration.${NC}"
    echo -e "${CYAN}We'll collect some information about your desired setup.${NC}\n"

    # Ask for number of peers
    local total_peers=0
    until [[ "$total_peers" =~ ^[1-9][0-9]*$ ]]; do
        echo -e "\n${CYAN}How many total peers (devices/clients) would you like to create?${NC}"
        read -r total_peers

        if [[ ! "$total_peers" =~ ^[1-9][0-9]*$ ]]; then
            log_error "Please enter a valid number"
        fi
    done

    # Auto-detect WireGuard port to use
    local wg_port=0
    local used_ports=()

    # Find already used ports
    if [ -d "/etc/wireguard" ]; then
        log_info "Checking for available ports..."
        while read -r port; do
            used_ports+=("$port")
        done < <(grep -r "ListenPort" /etc/wireguard --include="*.conf" 2>/dev/null | awk '{print $3}')
    fi

    # Start with default port and increment until we find an unused one
    wg_port=${DEFAULT_PORT}
    while [[ " ${used_ports[*]} " =~ " ${wg_port} " ]]; do
        wg_port=$((wg_port + 1))
    done

    echo -e "\n${CYAN}WireGuard Server Port${NC}"
    echo -e "${YELLOW}This UDP port needs to be opened in your firewall.${NC}"

    until [[ "$wg_port" =~ ^[0-9]+$ ]] && [ "$wg_port" -ge 1 ] && [ "$wg_port" -le 65535 ]; do
        read -rp "Enter server port [1-65535]: " -e -i "${wg_port}" wg_port

        if [[ ! "$wg_port" =~ ^[0-9]+$ ]] || [ "$wg_port" -lt 1 ] || [ "$wg_port" -gt 65535 ]; then
            log_error "Please enter a valid port number (1-65535)"
        fi
    done

    # Auto-detect and suggest IP subnet
    local last_octet=1
    # Find any existing subnets and avoid conflicts
    if [ -d "/etc/wireguard" ]; then
        while read -r subnet; do
            if [[ "$subnet" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+$ ]]; then
                local prefix=$(echo "$subnet" | cut -d. -f1-2)
                local third_octet=$(echo "$subnet" | cut -d. -f3)
                if [[ "$prefix" == "10.0" ]]; then
                    last_octet=$((third_octet + 1))
                fi
            fi
        done < <(grep -r "Address" /etc/wireguard --include="*.conf" 2>/dev/null | awk '{print $3}')
    fi

    echo -e "\n${CYAN}Internal VPN Network${NC}"
    echo -e "${YELLOW}This is the private network used within the VPN.${NC}"

    local server_subnet=""
    local suggested_subnet="10.0.${last_octet}.1/24"

    # Option to use 10.10.20.0/24 style addressing
    echo -e "\n${CYAN}VPN Subnet Style:${NC}"
    echo -e "1) Standard (e.g., 10.0.x.0/24)"
    echo -e "2) Alternative (e.g., 10.10.20.0/24)"

    local subnet_style
    read -rp "Select subnet style [1-2]: " subnet_style

    case $subnet_style in
        2)
            suggested_subnet="10.10.20.1/24"
            ;;
        *)
            suggested_subnet="10.0.${last_octet}.1/24"
            ;;
    esac

    until [[ $server_subnet =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/[0-9]{1,2}$ ]]; do
        read -rp "Enter server internal subnet [e.g. 10.0.0.1/24]: " -e -i "${suggested_subnet}" server_subnet

        if [[ ! $server_subnet =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/[0-9]{1,2}$ ]]; then
            log_error "Please enter a valid IP subnet (e.g., 10.0.0.1/24)"
        fi
    done

    # Extract base network for clients
    local base_network
    base_network=$(echo "$server_subnet" | cut -d'.' -f1-3)

    # Ask for DNS servers
    echo -e "\n${CYAN}DNS Servers${NC}"
    echo -e "${YELLOW}These DNS servers will be used by clients when connected to the VPN.${NC}"

    local dns_servers=""
    until [[ $dns_servers =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}(,[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})*$ ]]; do
        read -rp "DNS servers (comma separated): " -e -i "${DEFAULT_DNS}" dns_servers

        if [[ ! $dns_servers =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}(,[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})*$ ]]; then
            log_error "Please enter valid DNS servers (e.g., 1.1.1.1,1.0.0.1)"
        fi
    done

    # Auto-detect server public IP
    local detected_ip=""
    log_info "Detecting server public IP address..."

    # Try multiple services to find the public IP
    for ip_service in "ifconfig.me" "ipinfo.io/ip" "icanhazip.com"; do
        if detected_ip=$(curl -s "$ip_service" 2>/dev/null) && [[ $detected_ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
            log_info "Detected public IP: ${detected_ip}"
            break
        fi
    done

    # Fall back to local IP if public IP detection failed
    if [[ ! $detected_ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        detected_ip=$(ip -4 addr | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | grep -v "127.0.0.1" | head -n 1)
        log_warn "Could not detect public IP, using local IP: ${detected_ip}"
    fi

    # Ask for server public IP
    echo -e "\n${CYAN}Server Public IP or Hostname${NC}"
    echo -e "${YELLOW}This is how clients will connect to your server from the internet.${NC}"

    local server_public_ip=""
    read -rp "Public IP/Hostname: " -e -i "${detected_ip}" server_public_ip

    # Save the base config values for later use
    echo "WG_PORT=$wg_port" > config_values
    echo "SERVER_SUBNET=$server_subnet" >> config_values
    echo "BASE_NETWORK=$base_network" >> config_values
    echo "DNS_SERVERS=$dns_servers" >> config_values
    echo "SERVER_PUBLIC_IP=$server_public_ip" >> config_values
    echo "TOTAL_PEERS=$total_peers" >> config_values

    display_footer
}

# Configure clients/peers
configure_peers() {
    # Load saved values
    source config_values

    # Generate server keys
    log_info "Generating server cryptographic keys..."
    wg genkey | tee server.private | wg pubkey > server.public
    preshared_key=$(wg genpsk)
    echo "$preshared_key" > preshared.key

    # Initialize main server config
    log_info "Creating server configuration..."
    cat > wg0.conf <<EOF
# WireGuard Server Configuration
# Generated on $(date)
# Directory: $CONFIG_DIR

[Interface]
PrivateKey = $(cat server.private)
ListenPort = $WG_PORT
Address = $SERVER_SUBNET
DNS = $(echo "$BASE_NETWORK" | cut -d'.' -f1-3).1
# Uncomment for NAT/Internet routing:
# PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
# PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE
# Uncomment for IP forwarding:
# PreUp = sysctl -w net.ipv4.conf.all.forwarding=1
# MTU = 1420

EOF

    # Process each peer
    for i in $(seq 1 "$TOTAL_PEERS"); do
        display_header
        log_step "3.$i" "Configuring Peer $i of $TOTAL_PEERS"

        # Display server public key (users often need this)
        echo -e "\n${YELLOW}Server Public Key: ${CYAN}$(cat server.public)${NC}"
        echo -e "${YELLOW}This is needed when manually configuring clients.${NC}\n"

        # Get peer description
        echo -e "${CYAN}Enter a description for this peer:${NC}"
        echo -e "${YELLOW}Example: phone, laptop, home-router, office-pc${NC}"
        read -rp "Description: " peer_description

        # Store description
        CLIENT_DESCRIPTIONS+=("$peer_description")

        # Check if OpenWRT
        echo -e "\n${CYAN}Is this peer an OpenWRT router?${NC}"
        echo -e "${YELLOW}OpenWRT routers can route traffic from an entire network through the VPN.${NC}"

        if prompt_yes_no "Is peer $i an OpenWRT router?"; then
            is_openwrt="y"
            CLIENT_TYPES+=("router")
        else
            is_openwrt="n"
            CLIENT_TYPES+=("client")
        fi

        # Generate peer keys
        log_info "Generating cryptographic keys for peer $i ($peer_description)..."
        wg genkey | tee "peer${i}.private" | wg pubkey > "peer${i}.public"

        # Display the peer's public key
        echo -e "\n${YELLOW}Peer $i Public Key: ${CYAN}$(cat "peer${i}.public")${NC}"

        # Client IP in the VPN network
        client_ip="${BASE_NETWORK}.$((i+1))"
        CLIENTS+=("$client_ip")

        if [ "${is_openwrt,,}" = "y" ]; then
            # OpenWRT peer configuration
            # Extract VPN subnet from server address for inclusion
            local vpn_subnet=$(echo "$SERVER_SUBNET" | sed -E 's|([0-9]+\.[0-9]+\.[0-9]+)\.[0-9]+/([0-9]+)|\1.0/\2|')
            # Default common home network ranges, including the VPN subnet
            local default_networks="$vpn_subnet,192.168.1.0/24"

            # Check if there are multiple commonly used networks
            echo -e "\n${CYAN}Enter networks to route through this peer:${NC}"
            echo -e "${YELLOW}These are the networks behind your OpenWRT router that should be accessible through the VPN.${NC}"
            echo -e "${YELLOW}The VPN subnet ($vpn_subnet) is included by default to allow clients to communicate.${NC}"
            echo -e "${YELLOW}Common home networks: 192.168.1.0/24, 192.168.0.0/24, 10.0.0.0/24, 172.16.0.0/24${NC}"
            read -rp "Networks (comma separated): " -e -i "${default_networks}" allowed_networks

            # Store networks
            CLIENT_NETWORKS+=("$allowed_networks")

            # Add to main server config with multiple networks
            cat >> wg0.conf <<EOF

# Peer $i - OpenWRT Router - $peer_description
[Peer]
PublicKey = $(cat "peer${i}.public")
PresharedKey = $preshared_key
AllowedIPs = $allowed_networks
PersistentKeepalive = 25
EOF

            # Create OpenWRT-specific config
            cat > "peer${i}_openwrt.conf" <<EOF
# OpenWRT WireGuard Configuration for $peer_description
# Generated on $(date)
# Peer $i - VPN IP: $client_ip/24

===== OpenWRT Configuration Guide =====

1. On your OpenWRT router, install the WireGuard packages:
   opkg update
   opkg install wireguard wireguard-tools luci-app-wireguard

2. Go to Network → Interfaces → Add New Interface
   - Name: wg0
   - Protocol: WireGuard VPN

3. Enter these settings in the "General Settings" tab:
   - Private Key: $(cat "peer${i}.private")
   - Listen Port: $WG_PORT

4. Under "IP Addresses" add:
   - $client_ip/24

5. Under "Peers" add a new peer with:
   - Public Key: $(cat server.public)
   - Preshared Key: $preshared_key
   - Allowed IPs: 0.0.0.0/0
   - Route Allowed IPs: checked
   - Endpoint Host: $SERVER_PUBLIC_IP
   - Endpoint Port: $WG_PORT
   - Persistent Keep-Alive: 25

6. Under "Firewall Settings" select:
   - Create/Select a zone: WAN

7. Under Network → Firewall → Traffic Rules, add:
   - Forward traffic from 'lan' to 'wg0': Enable
   - Forward traffic from 'wg0' to 'lan': Enable

8. Networks being routed through this peer: $allowed_networks
   These networks should be accessible to other VPN clients.
EOF

            log_info "Created OpenWRT router configuration for peer $i"
            log_info "Router VPN Address: $client_ip/24"
            log_info "Networks Routed: $allowed_networks"
            log_info "Configuration File: peer${i}_openwrt.conf"

        else {
            # Regular client configuration
            # Add to main server config
            cat >> wg0.conf <<EOF

# Peer $i - Client - $peer_description
[Peer]
PublicKey = $(cat "peer${i}.public")
PresharedKey = $preshared_key
AllowedIPs = ${client_ip}/32
PersistentKeepalive = 25
EOF

            # Create client config file (for QR code generation)
            cat > "peer${i}_client.conf" <<EOF
[Interface]
# Client: $peer_description
PrivateKey = $(cat "peer${i}.private")
Address = ${client_ip}/24
DNS = $DNS_SERVERS

[Peer]
PublicKey = $(cat server.public)
PresharedKey = $preshared_key
AllowedIPs = 0.0.0.0/0
Endpoint = ${SERVER_PUBLIC_IP}:${WG_PORT}
PersistentKeepalive = 25
EOF

            log_info "Created client configuration for peer $i"
            log_info "Client VPN Address: $client_ip/24"
            log_info "Configuration File: peer${i}_client.conf"

            # Generate QR code if qrencode is installed
            if command -v qrencode &> /dev/null; then
                qrencode -t png -o "peer${i}_${peer_description}.png" < "peer${i}_client.conf"
                log_info "Generated QR code: peer${i}_${peer_description}.png"

                # For mobile devices, also show the QR code on the terminal
                echo -e "\n${YELLOW}QR Code for Mobile Device Setup:${NC}"
                echo -e "${YELLOW}Scan this with the WireGuard mobile app${NC}"
                qrencode -t ANSIUTF8 < "peer${i}_client.conf"
            else
                log_warn "qrencode not installed - skipping QR code generation"
            fi

            # Store an empty network for client types
            CLIENT_NETWORKS+=("")
        }
        fi

        display_footer
    done
}

# Create summary files
create_summary() {
    display_header
    log_step "4" "Creating Configuration Summary"

    # Load saved values if not already loaded
    if [ ! -v WG_PORT ]; then
        source config_values
    fi

    # Create a summary file
    log_info "Creating configuration summary..."
    cat > config_summary.txt <<EOF
=== WireGuard Configuration Summary ===
Generated on $(date)

SERVER CONFIGURATION:
- Directory: $CONFIG_DIR
- Public IP/Hostname: $SERVER_PUBLIC_IP
- Port: $WG_PORT/UDP
- Internal Network: $SERVER_SUBNET
- Public Key: $(cat server.public)
- Private Key: $(cat server.private)

PEER CONFIGURATIONS:
EOF

    # Add peer information to summary
    for i in $(seq 1 "$TOTAL_PEERS"); do
        peer_type=${CLIENT_TYPES[$((i-1))]}
        peer_desc=${CLIENT_DESCRIPTIONS[$((i-1))]}
        peer_ip=${CLIENTS[$((i-1))]}
        peer_networks=${CLIENT_NETWORKS[$((i-1))]}

        if [ "$peer_type" == "router" ]; then
            peer_type_desc="OpenWRT Router"
            networks_info="- Networks Routed: $peer_networks"
        else
            peer_type_desc="Client Device"
            networks_info=""
        fi

        cat >> config_summary.txt <<EOF

Peer $i:
- Type: $peer_type_desc
- Description: $peer_desc
- VPN IP Address: $peer_ip/24
- Public Key: $(cat "peer${i}.public")
- Private Key: $(cat "peer${i}.private")
$networks_info
- Config File: peer${i}_${peer_type}.conf
EOF

        if [ "$peer_type" == "client" ] && command -v qrencode &> /dev/null; then
            echo "- QR Code: peer${i}_${peer_desc}.png" >> config_summary.txt
        fi
    done

    cat >> config_summary.txt <<EOF

SETUP INSTRUCTIONS:
1. Copy wg0.conf to /etc/wireguard/ on the server
2. Enable the interface: systemctl enable --now wg-quick@wg0
3. Open UDP port $WG_PORT in your firewall
4. For clients, import the configuration or scan the QR code
5. For routers, follow the instructions in the peer*_openwrt.conf file
EOF

    log_info "Configuration summary created: config_summary.txt"
    display_footer
}

# Display results and next steps
display_results() {
    display_header
    log_step "5" "Configuration Complete - What To Do Next"

    # Load saved values if not already loaded
    if [ ! -v WG_PORT ]; then
        source config_values
    fi

    echo -e "${BOLD}${GREEN}✅ WireGuard configuration generation complete!${NC}\n"

    echo -e "${BOLD}${CYAN}=== SERVER SETUP INSTRUCTIONS ===${NC}"
    echo -e "${YELLOW}------------------------------------------${NC}"
    echo -e "1. ${BOLD}Copy the server config:${NC}"
    if [[ "$CONFIG_DIR" == /etc/wireguard/* ]]; then
        echo -e "   ✅ Server config already in the right location!"
    else
        echo -e "   ➤ Run: ${CYAN}cp $CONFIG_DIR/wg0.conf /etc/wireguard/${NC}"
    fi

    echo -e "2. ${BOLD}Start the WireGuard interface:${NC}"
    echo -e "   ➤ Run: ${CYAN}systemctl enable --now wg-quick@wg0${NC}"

    echo -e "3. ${BOLD}Configure your firewall:${NC}"
    echo -e "   ➤ Run: ${CYAN}ufw allow $WG_PORT/udp${NC} or equivalent for your firewall"

    echo -e "4. ${BOLD}Enable IP forwarding (for VPN routing):${NC}"
    echo -e "   ➤ Run: ${CYAN}echo \"net.ipv4.ip_forward=1\" >> /etc/sysctl.conf${NC}"
    echo -e "   ➤ Run: ${CYAN}sysctl -p${NC}"

    echo -e "5. ${BOLD}Check WireGuard status:${NC}"
    echo -e "   ➤ Run: ${CYAN}wg show${NC}"

    echo -e "\n${BOLD}${CYAN}=== CLIENT SETUP INSTRUCTIONS ===${NC}"
    echo -e "${YELLOW}------------------------------------------${NC}"

    # Process each peer for specific instructions
    for i in $(seq 1 "$TOTAL_PEERS"); do
        peer_type=${CLIENT_TYPES[$((i-1))]}
        peer_desc=${CLIENT_DESCRIPTIONS[$((i-1))]}
        peer_ip=${CLIENTS[$((i-1))]}

        echo -e "\n${BOLD}Peer $i: $peer_desc ${NC}(${peer_ip}/24)"

        if [ "$peer_type" == "router" ]; then
            echo -e "➤ ${BOLD}OpenWRT Router Setup:${NC}"
            echo -e "  • Configuration file: ${CYAN}$CONFIG_DIR/peer${i}_openwrt.conf${NC}"
            echo -e "  • Follow the detailed instructions in this file"
            echo -e "  • This router will route traffic from: ${GREEN}${CLIENT_NETWORKS[$((i-1))]}${NC}"
        else
            echo -e "➤ ${BOLD}Device Setup:${NC}"
            echo -e "  • Configuration file: ${CYAN}$CONFIG_DIR/peer${i}_client.conf${NC}"

            if command -v qrencode &> /dev/null; then
                echo -e "  • QR Code: ${CYAN}$CONFIG_DIR/peer${i}_${peer_desc}.png${NC}"
                echo -e "  • Mobile setup: Scan the QR code with the WireGuard app"
            else
                echo -e "  • Mobile setup: Import the configuration file into the WireGuard app"
            fi

            echo -e "  • Desktop setup: Import the configuration file into the WireGuard client"
        fi
    done

    echo -e "\n${BOLD}${CYAN}=== CONFIGURATION FILES ===${NC}"
    echo -e "${YELLOW}------------------------------------------${NC}"
    echo -e "${BOLD}All configurations are in:${NC} $CONFIG_DIR"
    echo -e "${BOLD}Summary file:${NC} $CONFIG_DIR/config_summary.txt"

    echo -e "\n${BOLD}${RED}⚠️ SECURITY REMINDER:${NC}"
    echo -e "Private keys should be kept secure. Consider deleting them after setup."

    display_footer
}

# Function to check WireGuard status
check_wg_status() {
    display_header

    # Title block
    echo -e "${BOLD}${CYAN}===============================================${NC}"
    echo -e "${BOLD}${CYAN}               WIREGUARD STATUS               ${NC}"
    echo -e "${BOLD}${CYAN}===============================================${NC}"
    echo

    # Check if any WireGuard interfaces are up
    if ! command -v wg &>/dev/null; then
        log_error "WireGuard tools not installed"
        display_footer
        return 1
    fi

    # Check active interfaces
    echo -e "${BOLD}${GREEN}=== ACTIVE WIREGUARD INTERFACES ===${NC}"

    if wg &>/dev/null; then
        # Capture the wg output
        local wg_output=$(wg)

        # Parse and display with better formatting
        local current_interface=""
        local in_peer=false

        while IFS= read -r line; do
            if [[ $line =~ ^interface:\ (.+)$ ]]; then
                current_interface="${BASH_REMATCH[1]}"
                echo -e "\n${GREEN}${BOLD}Interface: ${CYAN}${current_interface}${NC}"
                echo -e "${YELLOW}------------------------------------------${NC}"
                in_peer=false
            elif [[ $line =~ ^peer:\ (.+)$ ]]; then
                echo -e "\n${BLUE}${BOLD}Peer: ${NC}${BASH_REMATCH[1]}"
                echo -e "${YELLOW}------------------------------------------${NC}"
                in_peer=true
            elif [[ $line =~ ^[[:space:]]+public\ key:\ (.+)$ ]]; then
                echo -e "  ${BOLD}Public Key:${NC} ${BASH_REMATCH[1]}"
            elif [[ $line =~ ^[[:space:]]+private\ key:\ (.+)$ ]]; then
                echo -e "  ${BOLD}Private Key:${NC} ${BASH_REMATCH[1]}"
            elif [[ $line =~ ^[[:space:]]+listening\ port:\ (.+)$ ]]; then
                echo -e "  ${BOLD}Port:${NC} ${PURPLE}${BASH_REMATCH[1]}${NC}"
            elif [[ $line =~ ^[[:space:]]+endpoint:\ (.+)$ ]]; then
                echo -e "  ${BOLD}Endpoint:${NC} ${CYAN}${BASH_REMATCH[1]}${NC}"
            elif [[ $line =~ ^[[:space:]]+allowed\ ips:\ (.+)$ ]]; then
                echo -e "  ${BOLD}Allowed IPs:${NC} ${GREEN}${BASH_REMATCH[1]}${NC}"
            elif [[ $line =~ ^[[:space:]]+latest\ handshake:\ (.+)$ ]]; then
                echo -e "  ${BOLD}Handshake:${NC} ${YELLOW}${BASH_REMATCH[1]}${NC}"
            elif [[ $line =~ ^[[:space:]]+transfer:\ (.+)$ ]]; then
                echo -e "  ${BOLD}Transfer:${NC} ${BASH_REMATCH[1]}"
            elif [[ $line =~ ^[[:space:]]+persistent\ keepalive:\ (.+)$ ]]; then
                echo -e "  ${BOLD}Keepalive:${NC} ${BASH_REMATCH[1]}"
            elif [[ $line =~ ^[[:space:]]+preshared\ key:\ (.+)$ ]]; then
                echo -e "  ${BOLD}Preshared Key:${NC} ${BASH_REMATCH[1]}"
            else
                echo -e "  $line"
            fi
        done <<< "$wg_output"
    else
        echo -e "\n${YELLOW}No active WireGuard interfaces found${NC}"
    fi

    # Check systemd services
    echo -e "\n${BOLD}${GREEN}=== WIREGUARD SERVICES ===${NC}"

    # Check systemd services
    local wg_services=$(systemctl list-units --type=service --all | grep "wg-quick" || echo "")

    if [ -n "$wg_services" ]; then
        echo -e "${YELLOW}------------------------------------------${NC}"
        # Get service info and format it nicely
        while IFS= read -r service; do
            local service_name=$(echo "$service" | awk '{print $1}')
            local status=$(echo "$service" | awk '{print $3}')
            local sub_status=$(echo "$service" | awk '{print $4}')

            # Color-coded status
            local status_color="${RED}"
            if [[ "$status" == "active" ]]; then
                status_color="${GREEN}"
            fi

            echo -e "  ${BOLD}${service_name}${NC}"
            echo -e "    Status: ${status_color}${status}/${sub_status}${NC}"
        done <<< "$wg_services"
    else
        echo -e "\n${YELLOW}No WireGuard services found${NC}"
    fi

    # Check config files
    echo -e "\n${BOLD}${GREEN}=== WIREGUARD CONFIGURATIONS ===${NC}"

    if [ -d "/etc/wireguard" ]; then
        local conf_files=$(find /etc/wireguard -name "*.conf" 2>/dev/null || echo "")

        if [ -n "$conf_files" ]; then
            echo -e "${YELLOW}------------------------------------------${NC}"

            # Group by directory
            local prev_dir=""
            while IFS= read -r file; do
                local dir=$(dirname "$file")
                local filename=$(basename "$file")

                # If directory changed, print the new directory
                if [[ "$dir" != "$prev_dir" ]]; then
                    echo -e "\n  ${BOLD}${CYAN}Directory: ${dir}${NC}"
                    prev_dir="$dir"
                fi

                # Check if it's actively used
                if systemctl is-active --quiet "wg-quick@$(basename "$filename" .conf)"; then
                    echo -e "    ${GREEN}* ${filename}${NC} ${CYAN}(active)${NC}"
                else
                    echo -e "    ${YELLOW}- ${filename}${NC}"
                fi
            done <<< "$(find /etc/wireguard -name "*.conf" 2>/dev/null | sort)"
        else
            echo -e "\n${YELLOW}No WireGuard configuration files found in /etc/wireguard${NC}"
        fi
    else
        echo -e "\n${YELLOW}/etc/wireguard directory not found${NC}"
    fi

    # Traffic statistics if available
    if command -v ifconfig &>/dev/null && wg &>/dev/null; then
        echo -e "\n${BOLD}${GREEN}=== TRAFFIC STATISTICS ===${NC}"

        # Get active interfaces and show their statistics
        local interfaces=$(wg | grep "interface:" | awk '{print $2}')

        if [ -n "$interfaces" ]; then
            echo -e "${YELLOW}------------------------------------------${NC}"

            while IFS= read -r iface; do
                if ifconfig "$iface" &>/dev/null; then
                    echo -e "  ${BOLD}${CYAN}Interface: ${iface}${NC}"
                    # Extract and format RX/TX stats
                    local rx_bytes=$(ifconfig "$iface" | grep "RX packets" | awk '{print $5}')
                    local tx_bytes=$(ifconfig "$iface" | grep "TX packets" | awk '{print $5}')

                    # Convert to human-readable format if possible
                    if command -v numfmt &>/dev/null; then
                        rx_bytes=$(numfmt --to=iec --suffix=B "$rx_bytes" 2>/dev/null || echo "$rx_bytes bytes")
                        tx_bytes=$(numfmt --to=iec --suffix=B "$tx_bytes" 2>/dev/null || echo "$tx_bytes bytes")
                    else
                        rx_bytes="$rx_bytes bytes"
                        tx_bytes="$tx_bytes bytes"
                    fi

                    echo -e "    ${BOLD}RX:${NC} ${GREEN}$rx_bytes${NC}"
                    echo -e "    ${BOLD}TX:${NC} ${BLUE}$tx_bytes${NC}"
                fi
            done <<< "$interfaces"
        else
            echo -e "\n${YELLOW}No interface statistics available${NC}"
        fi
    fi

    display_footer
}

# List existing configurations
list_configs() {
    display_header
    echo -e "${BOLD}${CYAN}=== Existing WireGuard Configurations ===${NC}\n"

    local configs_found=0

    # Function to display configuration details
    display_config() {
        local dir=$1
        local folder_name=$(basename "$dir")
        local total_peers=0
        local server_port="Unknown"
        local server_subnet="Unknown"

        # Look for wg*.conf files
        for conf_file in "$dir"/wg*.conf; do
            if [ -f "$conf_file" ]; then
                total_peers=$(grep -c "^\# Peer" "$conf_file" 2>/dev/null || echo "0")
                server_port=$(grep "ListenPort" "$conf_file" 2>/dev/null | awk '{print $3}' || echo "Unknown")
                server_subnet=$(grep "Address" "$conf_file" 2>/dev/null | awk '{print $3}' || echo "Unknown")

                echo -e "${BOLD}${GREEN}Configuration: ${folder_name}${NC}"
                echo -e "${YELLOW}  - Config File:${NC} $(basename "$conf_file")"
                echo -e "${YELLOW}  - Server Port:${NC} $server_port"
                echo -e "${YELLOW}  - Server Subnet:${NC} $server_subnet"
                echo -e "${YELLOW}  - Total Peers:${NC} $total_peers"
                echo -e "${YELLOW}  - Directory:${NC} $(realpath "$dir")"
                echo

                configs_found=1
                break
            fi
        done
    }

    # First check the current directory
    echo -e "${BOLD}${PURPLE}Local configurations:${NC}"
    for dir in wg*/; do
        if [ -d "$dir" ]; then
            display_config "$dir"
        fi
    done

    # Then check /etc/wireguard
    if [ -d "/etc/wireguard" ]; then
        echo -e "${BOLD}${PURPLE}System configurations (/etc/wireguard):${NC}"

        # List direct config files in /etc/wireguard
        for conf_file in /etc/wireguard/*.conf; do
            if [ -f "$conf_file" ]; then
                local interface_name=$(basename "$conf_file" .conf)
                local total_peers=$(grep -c "^\[Peer\]" "$conf_file" 2>/dev/null || echo "0")
                local server_port=$(grep "ListenPort" "$conf_file" 2>/dev/null | awk '{print $3}' || echo "Unknown")
                local server_subnet=$(grep "Address" "$conf_file" 2>/dev/null | awk '{print $3}' || echo "Unknown")

                echo -e "${BOLD}${GREEN}Configuration: ${interface_name}${NC}"
                echo -e "${YELLOW}  - Active Interface: ${NC} $(systemctl is-active "wg-quick@${interface_name}" 2>/dev/null || echo "inactive")"
                echo -e "${YELLOW}  - Server Port:${NC} $server_port"
                echo -e "${YELLOW}  - Server Subnet:${NC} $server_subnet"
                echo -e "${YELLOW}  - Total Peers:${NC} $total_peers"
                echo -e "${YELLOW}  - Directory:${NC} /etc/wireguard"
                echo

                configs_found=1
            fi
        done

        # List subdirectories in /etc/wireguard
        for dir in /etc/wireguard/*/; do
            if [ -d "$dir" ]; then
                display_config "$dir"
            fi
        done
    else
        echo -e "${YELLOW}System configuration directory /etc/wireguard not found${NC}"
        echo
    fi

    if [ $configs_found -eq 0 ]; then
        echo -e "${YELLOW}No configurations found${NC}"
    fi

    display_footer
}

# Generate keys with walkthrough
generate_keys_walkthrough() {
    check_wireguard
    select_config_dir
    collect_basic_info
    configure_peers
    create_summary
    display_results

    echo -e "${GREEN}${BOLD}WireGuard configuration completed successfully!${NC}"
}

# Main menu
show_menu() {
    display_header

    echo -e "${BOLD}${YELLOW}╔════════════════════════════════════════╗${NC}"
    echo -e "${BOLD}${YELLOW}║            SELECT AN OPTION            ║${NC}"
    echo -e "${BOLD}${YELLOW}╚════════════════════════════════════════╝${NC}"
    echo
    echo -e "${GREEN}1)${NC} Generate new WireGuard configuration (walkthrough)"
    echo -e "${GREEN}2)${NC} List existing configurations"
    echo -e "${GREEN}3)${NC} Check WireGuard status"
    echo -e "${GREEN}4)${NC} Exit"
    echo
    echo -n -e "${CYAN}Enter option [1-4]:${NC} "
}

# Main function to run the script
main() {
    # Skip initial check since we'll do it when needed
    trap - ERR
    set +e

    # Main menu loop
    while true; do
        show_menu
        read -r choice

        case $choice in
            1) generate_keys_walkthrough ;;
            2) list_configs ;;
            3) check_wg_status ;;
            4)
                echo -e "${GREEN}Exiting...${NC}"
                exit 0
                ;;
            *)
                log_error "Invalid option"
                sleep 1
                ;;
        esac
    done
}

# Start the script
main
