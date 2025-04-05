#!/bin/bash

# Improved WireGuard VPN Server Installer
# Version 1.2.1

# Color definitions
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color
BOLD='\033[1m'

# Error handling
trap 'echo -e "\n${RED}[ERROR] Script failed at line $LINENO${NC}"; exit 1' ERR

# Display header function
display_header() {
    clear
    echo -e "${BLUE}${BOLD}===============================================${NC}"
    echo -e "${BLUE}${BOLD}       WireGuard VPN Installer v1.2.1       ${NC}"
    echo -e "${BLUE}${BOLD}===============================================${NC}"
    echo
}

# Display footer
display_footer() {
    echo
    echo -e "${BOLD}Press Enter to continue...${NC}"
    read -r
}

# Log functions
log_info()  { echo -e "${GREEN}[INFO]  $*${NC}"; }
log_warn()  { echo -e "${YELLOW}[WARN]  $*${NC}"; }
log_error() { echo -e "${RED}[ERROR] $*${NC}"; }

# Check if user is root
function isRoot() {
    if [ "${EUID}" -ne 0 ]; then
        log_error "You need to run this script as root"
        echo -e "${YELLOW}Try running: ${NC}sudo $0"
        exit 1
    fi
}

# Check for virtualization compatibility
function checkVirt() {
    if command -v systemd-detect-virt >/dev/null; then
        VIRT=$(systemd-detect-virt)

        case "$VIRT" in
            openvz)
                log_error "OpenVZ virtualization is not supported"
                exit 1
                ;;
            lxc)
                log_warn "LXC virtualization detected"
                echo -e "${YELLOW}NOTE: WireGuard can technically run in an LXC container,${NC}"
                echo -e "${YELLOW}but the kernel module must be installed on the host,${NC}"
                echo -e "${YELLOW}and the container must be run with specific parameters.${NC}"

                echo
                read -rp "Do you want to continue anyway? [y/N] " -e CONTINUE

                if [[ "$CONTINUE" != "y" && "$CONTINUE" != "Y" ]]; then
                    exit 1
                fi
                ;;
        esac
    else
        log_warn "systemd-detect-virt not found, skipping virtualization check"
    fi
}

# Check for kernel module support
function checkKernelSupport() {
    if ! grep -q '^CONFIG_WIREGUARD=[my]' /boot/config-"$(uname -r)" 2>/dev/null; then
        log_warn "WireGuard kernel module may not be available for your kernel"
        log_info "Will attempt to use DKMS or kernel module packages if available"
    else
        log_info "Kernel has built-in WireGuard support"
    fi
}

# Check OS compatibility
function checkOS() {
    if [[ -f /etc/os-release ]]; then
        source /etc/os-release
        OS="${ID}"

        case ${OS} in
            debian|raspbian)
                if [[ ${VERSION_ID} -lt 10 ]]; then
                    log_error "Your version of Debian/Raspbian (${VERSION_ID}) is not supported."
                    echo -e "${YELLOW}Please use Debian 10 Buster or later${NC}"
                    exit 1
                fi
                OS="debian" # Normalize OS name
                ;;
            ubuntu)
                RELEASE_YEAR=$(echo "${VERSION_ID}" | cut -d'.' -f1)
                if [[ ${RELEASE_YEAR} -lt 18 ]]; then
                    log_error "Your version of Ubuntu (${VERSION_ID}) is not supported."
                    echo -e "${YELLOW}Please use Ubuntu 18.04 or later${NC}"
                    exit 1
                fi
                ;;
            fedora)
                if [[ ${VERSION_ID} -lt 32 ]]; then
                    log_error "Your version of Fedora (${VERSION_ID}) is not supported."
                    echo -e "${YELLOW}Please use Fedora 32 or later${NC}"
                    exit 1
                fi
                ;;
            centos|almalinux|rocky)
                if [[ ${VERSION_ID} == 7* ]]; then
                    log_error "Your version of CentOS/AlmaLinux/Rocky (${VERSION_ID}) is not supported."
                    echo -e "${YELLOW}Please use version 8 or later${NC}"
                    exit 1
                fi
                ;;
            *)
                if [[ -e /etc/oracle-release ]]; then
                    source /etc/os-release
                    OS=oracle
                elif [[ -e /etc/arch-release ]]; then
                    OS=arch
                else
                    log_error "Unsupported operating system."
                    echo -e "${YELLOW}This installer supports: Debian, Ubuntu, Fedora, CentOS, AlmaLinux, Oracle or Arch Linux${NC}"
                    exit 1
                fi
                ;;
        esac
        log_info "Detected OS: ${OS} ${VERSION_ID}"
    else
        log_error "Could not determine OS type"
        exit 1
    fi
}

# Check for dependencies
function check_dependencies() {
    log_info "Checking dependencies..."

    local deps_to_install=()

    # Common tools needed
    for cmd in curl ip grep; do
        if ! command -v "$cmd" &>/dev/null; then
            deps_to_install+=("$cmd")
        fi
    done

    # Check for qrencode separately (optional but useful)
    if ! command -v qrencode &>/dev/null; then
        log_info "QR code generation capability (qrencode) will be installed"
        deps_to_install+=("qrencode")
    fi

    # Install missing dependencies if any
    if [ ${#deps_to_install[@]} -gt 0 ]; then
        log_info "Installing missing dependencies: ${deps_to_install[*]}"
        case ${OS} in
            debian|ubuntu)
                apt-get update -q
                apt-get install -y "${deps_to_install[@]}"
                ;;
            fedora|centos|almalinux|rocky|oracle)
                yum install -y "${deps_to_install[@]}"
                ;;
            arch)
                pacman -Sy --needed --noconfirm "${deps_to_install[@]}"
                ;;
            *)
                log_warn "Cannot install dependencies automatically on this OS."
                log_warn "Please manually install: ${deps_to_install[*]}"
                ;;
        esac
    else
        log_info "All required dependencies are installed"
    fi
}

# Get home directory for a client
function getHomeDirForClient() {
    local CLIENT_NAME=$1

    if [ -z "${CLIENT_NAME}" ]; then
        log_error "getHomeDirForClient() requires a client name as argument"
        exit 1
    fi

    # Home directory of the user, where the client configuration will be written
    if [ -e "/home/${CLIENT_NAME}" ]; then
        # if $1 is a user name
        HOME_DIR="/home/${CLIENT_NAME}"
    elif [ "${SUDO_USER}" ]; then
        # if not, use SUDO_USER
        if [ "${SUDO_USER}" == "root" ]; then
            # If running sudo as root
            HOME_DIR="/root"
        else
            HOME_DIR="/home/${SUDO_USER}"
        fi
    else
        # if not SUDO_USER, use /root
        HOME_DIR="/root"
    fi

    # Make sure the directory exists
    mkdir -p "$HOME_DIR" 2>/dev/null || true

    echo "$HOME_DIR"
}

# Run initial environment checks
function initialCheck() {
    display_header
    log_info "Performing initial system checks..."

    isRoot
    checkVirt
    checkOS
    checkKernelSupport
    check_dependencies

    log_info "All checks passed, continuing with installation"
}

# Installation questions for WireGuard setup
function installQuestions() {
    display_header
    echo -e "${BOLD}${CYAN}=== WireGuard Configuration ===${NC}\n"

    echo -e "${YELLOW}WireGuard is a modern VPN that uses state-of-the-art cryptography.${NC}"
    echo -e "${YELLOW}This installer will set up a WireGuard server on your system.${NC}"
    echo -e "\n${CYAN}Please answer the following questions to configure your VPN:${NC}\n"

    # Detect public IPv4 or IPv6 address
    SERVER_PUB_IP=$(ip -4 addr | sed -ne 's|^.* inet \([^/]*\)/.* scope global.*$|\1|p' | awk '{print $1}' | head -1)
    if [[ -z ${SERVER_PUB_IP} ]]; then
        # Try to get the public IP from an external service if available
        SERVER_PUB_IP=$(curl -s https://ipinfo.io/ip || curl -s https://api.ipify.org || curl -s https://icanhazip.com)

        # If still empty, try IPv6
        if [[ -z ${SERVER_PUB_IP} ]]; then
            SERVER_PUB_IP=$(ip -6 addr | sed -ne 's|^.* inet6 \([^/]*\)/.* scope global.*$|\1|p' | head -1)
        fi
    fi

    echo -e "${CYAN}Your server needs a public IP address for clients to connect to.${NC}"
    read -rp "Public IP address: " -e -i "${SERVER_PUB_IP}" SERVER_PUB_IP

    # Detect public interface
    SERVER_NIC="$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1)"
    echo -e "\n${CYAN}The public interface is the network interface connected to the internet.${NC}"
    until [[ ${SERVER_PUB_NIC} =~ ^[a-zA-Z0-9_]+$ ]]; do
        read -rp "Public interface: " -e -i "${SERVER_NIC}" SERVER_PUB_NIC
    done

    echo -e "\n${CYAN}The WireGuard interface is a virtual network interface created for this VPN.${NC}"
    until [[ ${SERVER_WG_NIC} =~ ^[a-zA-Z0-9_]+$ && ${#SERVER_WG_NIC} -lt 16 ]]; do
        read -rp "WireGuard interface name: " -e -i wg0 SERVER_WG_NIC
    done

    echo -e "\n${CYAN}The WireGuard server needs an internal IPv4 address.${NC}"
    until [[ ${SERVER_WG_IPV4} =~ ^([0-9]{1,3}\.){3} ]]; do
        read -rp "Server WireGuard IPv4: " -e -i 10.66.66.1 SERVER_WG_IPV4
    done

    echo -e "\n${CYAN}Similarly, the server needs an internal IPv6 address for the VPN network.${NC}"
    until [[ ${SERVER_WG_IPV6} =~ ^([a-f0-9]{1,4}:){3,4}: ]]; do
        read -rp "Server WireGuard IPv6: " -e -i fd42:42:42::1 SERVER_WG_IPV6
    done

    # Generate random number within private ports range
    RANDOM_PORT=$(shuf -i49152-65535 -n1 2>/dev/null || echo "51820")
    echo -e "\n${CYAN}WireGuard needs a UDP port to listen for incoming connections.${NC}"
    until [[ ${SERVER_PORT} =~ ^[0-9]+$ ]] && [ "${SERVER_PORT}" -ge 1 ] && [ "${SERVER_PORT}" -le 65535 ]; do
        read -rp "Server WireGuard port [1-65535]: " -e -i "${RANDOM_PORT}" SERVER_PORT
    done

    echo -e "\n${CYAN}VPN clients will use these DNS servers while connected.${NC}"
    # Cloudflare DNS by default
    until [[ ${CLIENT_DNS_1} =~ ^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$ ]]; do
        read -rp "First DNS resolver for clients: " -e -i 1.1.1.1 CLIENT_DNS_1
    done
    until [[ ${CLIENT_DNS_2} =~ ^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$ ]]; do
        read -rp "Second DNS resolver for clients (optional): " -e -i 1.0.0.1 CLIENT_DNS_2
        if [[ ${CLIENT_DNS_2} == "" ]]; then
            CLIENT_DNS_2="${CLIENT_DNS_1}"
        fi
    done

    echo -e "\n${CYAN}WireGuard uses AllowedIPs to determine what traffic is routed through the VPN.${NC}"
    echo -e "${CYAN}Default setting (0.0.0.0/0,::/0) routes ALL traffic through the VPN.${NC}"
    until [[ ${ALLOWED_IPS} =~ ^.+$ ]]; do
        read -rp "Allowed IPs for clients [0.0.0.0/0,::/0 = route all traffic]: " -e -i '0.0.0.0/0,::/0' ALLOWED_IPS
        if [[ ${ALLOWED_IPS} == "" ]]; then
            ALLOWED_IPS="0.0.0.0/0,::/0"
        fi
    done

    echo -e "\n${GREEN}${BOLD}✅ Configuration complete!${NC}"
    echo -e "${CYAN}The WireGuard server will now be installed and configured.${NC}"
    read -n1 -r -p "Press any key to continue..."
}

# Install WireGuard server
function installWireGuard() {
    # Run setup questions first
    installQuestions

    display_header
    log_info "Installing WireGuard server..."

    # Install WireGuard tools and module based on OS
    if [[ ${OS} == 'ubuntu' ]] || [[ ${OS} == 'debian' && ${VERSION_ID} -gt 10 ]]; then
        log_info "Installing WireGuard packages for ${OS}..."
        apt-get update
        apt-get install -y wireguard iptables resolvconf qrencode
    elif [[ ${OS} == 'debian' ]]; then
        log_info "Installing WireGuard packages for Debian Buster..."
        if ! grep -rqs "^deb .* buster-backports" /etc/apt/; then
            echo "deb http://deb.debian.org/debian buster-backports main" >/etc/apt/sources.list.d/backports.list
            apt-get update
        fi
        apt update
        apt-get install -y iptables resolvconf qrencode
        apt-get install -y -t buster-backports wireguard
    elif [[ ${OS} == 'fedora' ]]; then
        log_info "Installing WireGuard packages for Fedora..."
        if [[ ${VERSION_ID} -lt 32 ]]; then
            dnf install -y dnf-plugins-core
            dnf copr enable -y jdoss/wireguard
            dnf install -y wireguard-dkms
        fi
        dnf install -y wireguard-tools iptables qrencode
    elif [[ ${OS} == 'centos' ]] || [[ ${OS} == 'almalinux' ]] || [[ ${OS} == 'rocky' ]]; then
        log_info "Installing WireGuard packages for CentOS/AlmaLinux/Rocky..."
        if [[ ${VERSION_ID} == 8* ]]; then
            yum install -y epel-release elrepo-release
            yum install -y kmod-wireguard
            yum install -y qrencode # not available on release 9
        fi
        yum install -y wireguard-tools iptables
    elif [[ ${OS} == 'oracle' ]]; then
        log_info "Installing WireGuard packages for Oracle Linux..."
        dnf install -y oraclelinux-developer-release-el8
        dnf config-manager --disable -y ol8_developer
        dnf config-manager --enable -y ol8_developer_UEKR6
        dnf config-manager --save -y --setopt=ol8_developer_UEKR6.includepkgs='wireguard-tools*'
        dnf install -y wireguard-tools qrencode iptables
    elif [[ ${OS} == 'arch' ]]; then
        log_info "Installing WireGuard packages for Arch Linux..."
        pacman -S --needed --noconfirm wireguard-tools qrencode
    fi

    # Check if WireGuard was installed successfully
    if ! command -v wg &>/dev/null; then
        log_error "WireGuard installation failed"
        exit 1
    fi

    # Make sure the directory exists
    log_info "Setting up WireGuard configuration directory..."
    mkdir -p /etc/wireguard >/dev/null 2>&1
    chmod 600 -R /etc/wireguard/

    log_info "Generating WireGuard server keys..."
    SERVER_PRIV_KEY=$(wg genkey)
    SERVER_PUB_KEY=$(echo "${SERVER_PRIV_KEY}" | wg pubkey)

    log_info "Server public key: ${SERVER_PUB_KEY}"

    # Save WireGuard settings
    log_info "Saving WireGuard configuration parameters..."
    echo "SERVER_PUB_IP=${SERVER_PUB_IP}
SERVER_PUB_NIC=${SERVER_PUB_NIC}
SERVER_WG_NIC=${SERVER_WG_NIC}
SERVER_WG_IPV4=${SERVER_WG_IPV4}
SERVER_WG_IPV6=${SERVER_WG_IPV6}
SERVER_PORT=${SERVER_PORT}
SERVER_PRIV_KEY=${SERVER_PRIV_KEY}
SERVER_PUB_KEY=${SERVER_PUB_KEY}
CLIENT_DNS_1=${CLIENT_DNS_1}
CLIENT_DNS_2=${CLIENT_DNS_2}
ALLOWED_IPS=${ALLOWED_IPS}" >/etc/wireguard/params

    # Add server interface configuration
    log_info "Creating WireGuard server configuration file..."
    echo "[Interface]
Address = ${SERVER_WG_IPV4}/24,${SERVER_WG_IPV6}/64
ListenPort = ${SERVER_PORT}
PrivateKey = ${SERVER_PRIV_KEY}" >"/etc/wireguard/${SERVER_WG_NIC}.conf"

    # Configure firewall and forwarding rules based on what's available
    if pgrep firewalld; then
        log_info "Configuring FirewallD rules..."
        FIREWALLD_IPV4_ADDRESS=$(echo "${SERVER_WG_IPV4}" | cut -d"." -f1-3)".0"
        FIREWALLD_IPV6_ADDRESS=$(echo "${SERVER_WG_IPV6}" | sed 's/:[^:]*$/:0/')
        echo "PostUp = firewall-cmd --add-port ${SERVER_PORT}/udp && firewall-cmd --add-rich-rule='rule family=ipv4 source address=${FIREWALLD_IPV4_ADDRESS}/24 masquerade' && firewall-cmd --add-rich-rule='rule family=ipv6 source address=${FIREWALLD_IPV6_ADDRESS}/24 masquerade'
PostDown = firewall-cmd --remove-port ${SERVER_PORT}/udp && firewall-cmd --remove-rich-rule='rule family=ipv4 source address=${FIREWALLD_IPV4_ADDRESS}/24 masquerade' && firewall-cmd --remove-rich-rule='rule family=ipv6 source address=${FIREWALLD_IPV6_ADDRESS}/24 masquerade'" >>"/etc/wireguard/${SERVER_WG_NIC}.conf"
    else
        log_info "Configuring iptables rules..."
        echo "PostUp = iptables -I INPUT -p udp --dport ${SERVER_PORT} -j ACCEPT
PostUp = iptables -I FORWARD -i ${SERVER_PUB_NIC} -o ${SERVER_WG_NIC} -j ACCEPT
PostUp = iptables -I FORWARD -i ${SERVER_WG_NIC} -j ACCEPT
PostUp = iptables -t nat -A POSTROUTING -o ${SERVER_PUB_NIC} -j MASQUERADE
PostUp = ip6tables -I FORWARD -i ${SERVER_WG_NIC} -j ACCEPT
PostUp = ip6tables -t nat -A POSTROUTING -o ${SERVER_PUB_NIC} -j MASQUERADE
PostDown = iptables -D INPUT -p udp --dport ${SERVER_PORT} -j ACCEPT
PostDown = iptables -D FORWARD -i ${SERVER_PUB_NIC} -o ${SERVER_WG_NIC} -j ACCEPT
PostDown = iptables -D FORWARD -i ${SERVER_WG_NIC} -j ACCEPT
PostDown = iptables -t nat -D POSTROUTING -o ${SERVER_PUB_NIC} -j MASQUERADE
PostDown = ip6tables -D FORWARD -i ${SERVER_WG_NIC} -j ACCEPT
PostDown = ip6tables -t nat -D POSTROUTING -o ${SERVER_PUB_NIC} -j MASQUERADE" >>"/etc/wireguard/${SERVER_WG_NIC}.conf"
    fi

    # Enable routing on the server
    log_info "Enabling IP forwarding for VPN traffic routing..."
    echo "net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1" >/etc/sysctl.d/wg.conf

    sysctl --system

    log_info "Starting WireGuard service..."
    systemctl start "wg-quick@${SERVER_WG_NIC}"
    systemctl enable "wg-quick@${SERVER_WG_NIC}"

    # Create first client
    log_info "Setting up first client configuration..."
    newClient

    # Check if WireGuard is running
    systemctl is-active --quiet "wg-quick@${SERVER_WG_NIC}"
    WG_RUNNING=$?

    # WireGuard might not work if we updated the kernel. Tell the user to reboot
    if [[ ${WG_RUNNING} -ne 0 ]]; then
        log_error "WireGuard does not seem to be running."
        echo -e "${YELLOW}You can check WireGuard status with:${NC} systemctl status wg-quick@${SERVER_WG_NIC}"
        echo -e "${YELLOW}If you see 'Cannot find device ${SERVER_WG_NIC}', please reboot your system!${NC}"
    else # WireGuard is running
        showPostInstallInstructions
    fi
}

# Create a new client configuration - FIXED VERSION
function newClient() {
    display_header
    echo -e "${BOLD}${CYAN}=== Create New WireGuard Client ===${NC}\n"

    # Initialize variables to avoid unbound variable errors
    CLIENT_EXISTS=0
    IPV4_EXISTS=0
    IPV6_EXISTS=0

    # Load WireGuard parameters if not already loaded
    if [[ -z "${SERVER_WG_NIC}" ]]; then
        if [[ -f /etc/wireguard/params ]]; then
            source /etc/wireguard/params
        else
            log_error "WireGuard parameters file not found"
            exit 1
        fi
    fi

    # If SERVER_PUB_IP is IPv6, add brackets if missing
    if [[ ${SERVER_PUB_IP} =~ .*:.* ]]; then
        if [[ ${SERVER_PUB_IP} != *"["* ]] || [[ ${SERVER_PUB_IP} != *"]"* ]]; then
            SERVER_PUB_IP="[${SERVER_PUB_IP}]"
        fi
    fi
    ENDPOINT="${SERVER_PUB_IP}:${SERVER_PORT}"

    echo -e "${CYAN}WireGuard client configuration setup${NC}"
    echo -e "${YELLOW}Each client needs a unique name and IP address${NC}\n"
    echo -e "${YELLOW}The client name must consist of alphanumeric characters, underscores, or dashes${NC}"
    echo -e "${YELLOW}Client name must be 1-15 characters long${NC}\n"

    # Get a valid client name
    CLIENT_NAME=""
    until [[ ${CLIENT_NAME} =~ ^[a-zA-Z0-9_-]+$ && ${#CLIENT_NAME} -lt 16 ]]; do
        read -rp "Client name: " -e CLIENT_NAME

        # Check if name exists
        if [[ -f /etc/wireguard/${SERVER_WG_NIC}.conf ]]; then
            CLIENT_EXISTS=$(grep -c -E "^### Client ${CLIENT_NAME}\$" "/etc/wireguard/${SERVER_WG_NIC}.conf")
            if [[ ${CLIENT_EXISTS} -ne 0 ]]; then
                echo -e "${ORANGE}A client with the name '${CLIENT_NAME}' already exists, please choose another name.${NC}"
                CLIENT_NAME=""
            fi
        fi

        if [[ -z "${CLIENT_NAME}" ]]; then
            echo -e "${YELLOW}Please enter a valid client name.${NC}"
        fi
    done

    # Find a vacant IP in the VPN subnet
    log_info "Finding available IP address for client..."
    BASE_IP=$(echo "$SERVER_WG_IPV4" | awk -F '.' '{ print $1"."$2"."$3 }')

    # Find available IP
    DOT_IP=""
    for i in {2..254}; do
        if ! grep -q "${BASE_IP}.${i}" "/etc/wireguard/${SERVER_WG_NIC}.conf"; then
            DOT_IP="$i"
            break
        fi
    done

    if [[ -z "$DOT_IP" ]]; then
        log_error "No available IP addresses in the subnet ${BASE_IP}.0/24"
        echo -e "${YELLOW}The subnet configured supports only 253 clients and all IPs are taken.${NC}"
        exit 1
    fi

    # Confirm the IP with user
    CLIENT_WG_IPV4="${BASE_IP}.${DOT_IP}"
    echo -e "${CYAN}Suggested IPv4 address: ${CLIENT_WG_IPV4}${NC}"
    read -rp "Client WireGuard IPv4 [Enter to accept]: " -e CLIENT_IPV4_INPUT

    if [[ -n "$CLIENT_IPV4_INPUT" ]]; then
        CLIENT_WG_IPV4="$CLIENT_IPV4_INPUT"
        # Verify the IP is not already in use
        if grep -q "$CLIENT_WG_IPV4" "/etc/wireguard/${SERVER_WG_NIC}.conf"; then
            log_error "IP address ${CLIENT_WG_IPV4} is already in use"
            return 1
        fi
    fi

    # Find IPv6 for the client
    BASE_IPV6=$(echo "$SERVER_WG_IPV6" | awk -F '::' '{ print $1 }')
    CLIENT_WG_IPV6="${BASE_IPV6}::${DOT_IP}"
    echo -e "${CYAN}Client IPv6 address: ${CLIENT_WG_IPV6}${NC}"

    # Generate key pair for the client
    log_info "Generating cryptographic keys for the client..."
    CLIENT_PRIV_KEY=$(wg genkey)
    if [[ -z "$CLIENT_PRIV_KEY" ]]; then
        log_error "Failed to generate client private key"
        exit 1
    fi

    CLIENT_PUB_KEY=$(echo "${CLIENT_PRIV_KEY}" | wg pubkey)
    if [[ -z "$CLIENT_PUB_KEY" ]]; then
        log_error "Failed to generate client public key"
        exit 1
    fi

    CLIENT_PRE_SHARED_KEY=$(wg genpsk)
    if [[ -z "$CLIENT_PRE_SHARED_KEY" ]]; then
        log_error "Failed to generate pre-shared key"
        exit 1
    fi

    # Get home directory for client
    HOME_DIR=$(getHomeDirForClient "${CLIENT_NAME}")
    if [[ ! -d "$HOME_DIR" ]]; then
        log_warn "Directory $HOME_DIR does not exist, creating it..."
        mkdir -p "$HOME_DIR"
    fi

    log_info "Client configuration will be saved to: ${HOME_DIR}/${SERVER_WG_NIC}-client-${CLIENT_NAME}.conf"

    # Create client file and add the server as a peer
    echo -e "${CYAN}Creating client configuration file...${NC}"
    echo "[Interface]
PrivateKey = ${CLIENT_PRIV_KEY}
Address = ${CLIENT_WG_IPV4}/32,${CLIENT_WG_IPV6}/128
DNS = ${CLIENT_DNS_1},${CLIENT_DNS_2}

[Peer]
PublicKey = ${SERVER_PUB_KEY}
PresharedKey = ${CLIENT_PRE_SHARED_KEY}
Endpoint = ${ENDPOINT}
AllowedIPs = ${ALLOWED_IPS}" >"${HOME_DIR}/${SERVER_WG_NIC}-client-${CLIENT_NAME}.conf"

    # Check if the client config was created successfully
    if [[ ! -f "${HOME_DIR}/${SERVER_WG_NIC}-client-${CLIENT_NAME}.conf" ]]; then
        log_error "Failed to create client configuration file"
        exit 1
    fi

    # Add the client as a peer to the server
    echo -e "${CYAN}Adding client to server configuration...${NC}"
    echo -e "\n### Client ${CLIENT_NAME}
[Peer]
PublicKey = ${CLIENT_PUB_KEY}
PresharedKey = ${CLIENT_PRE_SHARED_KEY}
AllowedIPs = ${CLIENT_WG_IPV4}/32,${CLIENT_WG_IPV6}/128" >>"/etc/wireguard/${SERVER_WG_NIC}.conf"

    # Apply the configuration to the running WireGuard interface
    log_info "Applying configuration to WireGuard interface..."
    if command -v wg >/dev/null && [[ -f "/etc/wireguard/${SERVER_WG_NIC}.conf" ]]; then
        # First try the standard syncconf method
        if ! wg syncconf "${SERVER_WG_NIC}" <(wg-quick strip "${SERVER_WG_NIC}") 2>/dev/null; then
            log_warn "wg syncconf failed, trying alternative method..."
            # If that fails, try restarting the service
            systemctl restart "wg-quick@${SERVER_WG_NIC}"
        fi
    else
        log_warn "Could not update running WireGuard configuration, manual restart may be needed"
    fi

    # Generate QR code if qrencode is installed
    if command -v qrencode &>/dev/null; then
        echo -e "\n${GREEN}Here is your client config file as a QR Code:${NC}"
        echo -e "${YELLOW}Scan this QR code with your mobile device's WireGuard app${NC}"
        qrencode -t ansiutf8 -l L <"${HOME_DIR}/${SERVER_WG_NIC}-client-${CLIENT_NAME}.conf" || echo -e "${YELLOW}QR code generation failed, but configuration file was created successfully${NC}"
        echo ""
    else
        echo -e "\n${YELLOW}QR code generation tool (qrencode) is not installed.${NC}"
        echo -e "${YELLOW}Install it for easier mobile client setup.${NC}"
    fi

    # Print success message and instructions
    echo -e "${GREEN}✅ Client configuration complete!${NC}"
    echo -e "${GREEN}Client config file: ${HOME_DIR}/${SERVER_WG_NIC}-client-${CLIENT_NAME}.conf${NC}"
    echo -e "${YELLOW}For Windows/macOS/Linux clients: Copy this file to your device and import it${NC}"
    echo -e "${YELLOW}For mobile devices: Scan the QR code with the WireGuard app${NC}"
}

# Show post-installation instructions
function showPostInstallInstructions() {
    display_header
    echo -e "${BOLD}${GREEN}✅ WireGuard VPN Setup Complete!${NC}\n"

    echo -e "${GREEN}Your WireGuard server is now active and running.${NC}"
    echo -e "${CYAN}Port: ${SERVER_PORT}/UDP${NC}"
    echo -e "${CYAN}Interface: ${SERVER_WG_NIC}${NC}"
    echo -e "${CYAN}Server IP (internal): ${SERVER_WG_IPV4}${NC}"

    echo -e "\n${BOLD}${YELLOW}Client Connection Information:${NC}"
    echo -e "${YELLOW}- Client configuration files are stored in the home directory${NC}"
    echo -e "${YELLOW}- Mobile clients can scan the QR code to connect${NC}"
    echo -e "${YELLOW}- Use 'sudo $0' to manage clients and view the admin menu${NC}"

    echo -e "\n${BOLD}${CYAN}What to do next:${NC}"
    echo -e "${CYAN}1. Connect your devices using the client configuration files${NC}"
    echo -e "${CYAN}2. Check connection status with: ${NC}sudo wg show"
    echo -e "${CYAN}3. Verify network routing with: ${NC}ip route"

    display_footer
}

# List existing clients
function listClients() {
    display_header
    echo -e "${BOLD}${CYAN}=== WireGuard Client List ===${NC}\n"

    # Check if the config file exists
    if [[ ! -f "/etc/wireguard/${SERVER_WG_NIC}.conf" ]]; then
        log_error "WireGuard configuration file not found"
        display_footer
        return 1
    fi

    NUMBER_OF_CLIENTS=$(grep -c -E "^### Client" "/etc/wireguard/${SERVER_WG_NIC}.conf" || echo "0")
    if [[ ${NUMBER_OF_CLIENTS} -eq 0 ]]; then
        echo -e "${YELLOW}You have no existing clients!${NC}"
        display_footer
        return 1
    fi

    echo -e "${YELLOW}Existing WireGuard clients:${NC}"
    echo -e "${YELLOW}------------------------------------------${NC}"

    CLIENTS=$(grep -E "^### Client" "/etc/wireguard/${SERVER_WG_NIC}.conf" | cut -d ' ' -f 3)

    # For each client, extract the IP addresses
    i=1
    while IFS= read -r client; do
        # More reliable method to extract the IP address
        CLIENT_IP=$(grep -A 4 "^### Client ${client}$" "/etc/wireguard/${SERVER_WG_NIC}.conf" | grep "AllowedIPs" | cut -d '=' -f2 | awk '{print $1}' | cut -d'/' -f1 | tr -d ' ')
        echo -e "${GREEN}${i})${NC} ${CYAN}${client}${NC} - ${YELLOW}IP: ${CLIENT_IP}${NC}"
        ((i++))
    done <<< "${CLIENTS}"

    echo -e "\n${CYAN}Total Clients: ${NUMBER_OF_CLIENTS}${NC}"

    display_footer
}

# Safely revoke a client without hard-coded values
function revokeClient() {
    display_header
    echo -e "${BOLD}${CYAN}=== Revoke WireGuard Client ===${NC}\n"

    # Check if the config file exists
    if [[ ! -f "/etc/wireguard/${SERVER_WG_NIC}.conf" ]]; then
        log_error "WireGuard configuration file not found"
        display_footer
        return 1
    fi

    NUMBER_OF_CLIENTS=$(grep -c -E "^### Client" "/etc/wireguard/${SERVER_WG_NIC}.conf" || echo "0")
    if [[ ${NUMBER_OF_CLIENTS} -eq 0 ]]; then
        echo -e "${YELLOW}You have no existing clients!${NC}"
        display_footer
        return 1
    fi

    echo -e "${YELLOW}Select the client you want to revoke:${NC}"
    echo -e "${YELLOW}------------------------------------------${NC}"
    grep -E "^### Client" "/etc/wireguard/${SERVER_WG_NIC}.conf" | cut -d ' ' -f 3 | nl -s ') '
    echo -e "\n${YELLOW}Note: This action cannot be undone. The client will lose VPN access.${NC}"

    CLIENT_NUMBER=""
    until [[ ${CLIENT_NUMBER} =~ ^[0-9]+$ ]] && [[ ${CLIENT_NUMBER} -ge 1 ]] && [[ ${CLIENT_NUMBER} -le ${NUMBER_OF_CLIENTS} ]]; do
        read -rp "Select client [1-${NUMBER_OF_CLIENTS}]: " CLIENT_NUMBER

        if [[ ! ${CLIENT_NUMBER} =~ ^[0-9]+$ ]] || [[ ${CLIENT_NUMBER} -lt 1 ]] || [[ ${CLIENT_NUMBER} -gt ${NUMBER_OF_CLIENTS} ]]; then
            echo -e "${RED}Please enter a number between 1 and ${NUMBER_OF_CLIENTS}${NC}"
        fi
    done

    # Get the client name
    CLIENT_NAME=$(grep -E "^### Client" "/etc/wireguard/${SERVER_WG_NIC}.conf" | cut -d ' ' -f 3 | sed -n "${CLIENT_NUMBER}"p)
    if [[ -z "$CLIENT_NAME" ]]; then
        log_error "Failed to get client name"
        return 1
    fi

    # Create a backup of the config file before making changes
    CONFIG_BACKUP="/etc/wireguard/${SERVER_WG_NIC}.conf.bak.$(date +%s)"
    cp "/etc/wireguard/${SERVER_WG_NIC}.conf" "$CONFIG_BACKUP"
    log_info "Created backup of config at: $CONFIG_BACKUP"

    # Find the line numbers where the client section starts and ends
    START_LINE=$(grep -n "^### Client ${CLIENT_NAME}$" "/etc/wireguard/${SERVER_WG_NIC}.conf" | cut -d: -f1)

    if [[ -z "$START_LINE" ]]; then
        log_error "Could not find client ${CLIENT_NAME} in the configuration file"
        return 1
    fi

    # Find the next client marker or end of file
    NEXT_CLIENT_LINE=$(tail -n +$((START_LINE + 1)) "/etc/wireguard/${SERVER_WG_NIC}.conf" | grep -n "^### Client" | head -1 | cut -d: -f1)

    if [[ -n "$NEXT_CLIENT_LINE" ]]; then
        END_LINE=$((START_LINE + NEXT_CLIENT_LINE - 1))
    else
        # If no next client, use the end of file
        END_LINE=$(wc -l < "/etc/wireguard/${SERVER_WG_NIC}.conf")
    fi

    log_info "Removing client section for '${CLIENT_NAME}' (lines ${START_LINE}-${END_LINE})"

    # Create a new config file without the client section
    NEW_CONFIG="/etc/wireguard/${SERVER_WG_NIC}.conf.new"

    # Part before client section
    if [[ $START_LINE -gt 1 ]]; then
        head -n $((START_LINE - 1)) "/etc/wireguard/${SERVER_WG_NIC}.conf" > "$NEW_CONFIG"
    else
        # If client is at the start, create empty file
        > "$NEW_CONFIG"
    fi

    # Part after client section (if any)
    if [[ $END_LINE -lt $(wc -l < "/etc/wireguard/${SERVER_WG_NIC}.conf") ]]; then
        tail -n +$((END_LINE + 1)) "/etc/wireguard/${SERVER_WG_NIC}.conf" >> "$NEW_CONFIG"
    fi

    # Validate the new config
    if [[ ! -s "$NEW_CONFIG" ]]; then
        log_error "Generated configuration file is empty! Keeping original configuration."
        rm -f "$NEW_CONFIG"
    else
        # Count the [Peer] sections in both files to make sure we're only removing one
        OLD_PEER_COUNT=$(grep -c "^\[Peer\]" "/etc/wireguard/${SERVER_WG_NIC}.conf")
        NEW_PEER_COUNT=$(grep -c "^\[Peer\]" "$NEW_CONFIG")

        # We should have exactly one less peer
        EXPECTED_NEW_COUNT=$((OLD_PEER_COUNT - 1))

        if [[ "$NEW_PEER_COUNT" -eq "$EXPECTED_NEW_COUNT" || "$OLD_PEER_COUNT" -eq "$NEW_PEER_COUNT" ]]; then
            # Looks good, replace the file (second condition handles cases where the peer section might be malformed)
            mv "$NEW_CONFIG" "/etc/wireguard/${SERVER_WG_NIC}.conf"
            log_info "Successfully updated configuration file"
        else
            log_error "New configuration doesn't have the expected number of peers!"
            log_error "Expected: $EXPECTED_NEW_COUNT, Found: $NEW_PEER_COUNT"
            log_error "Keeping original configuration for safety."
            rm -f "$NEW_CONFIG"
        fi
    fi

    # Find and remove the client file
    log_info "Searching for client configuration file to delete..."

    # Try different directories where the client config might be
    POSSIBLE_DIRS=("/root" "/home/datea" "/home/${SUDO_USER}" "/home/${CLIENT_NAME}" "$(pwd)")
    CLIENT_FOUND=0

    for DIR in "${POSSIBLE_DIRS[@]}"; do
        if [[ -d "$DIR" ]]; then
            CLIENT_FILE="${DIR}/${SERVER_WG_NIC}-client-${CLIENT_NAME}.conf"
            if [[ -f "$CLIENT_FILE" ]]; then
                log_info "Found client file: $CLIENT_FILE"
                if rm -f "$CLIENT_FILE"; then
                    log_info "Successfully deleted client configuration file"
                    CLIENT_FOUND=1
                else
                    log_warn "Could not remove client configuration file: $CLIENT_FILE"
                fi
            fi
        fi
    done

    if [[ $CLIENT_FOUND -eq 0 ]]; then
        log_warn "Could not find client configuration file to delete"
        echo -e "${YELLOW}You may need to manually delete the file: ${SERVER_WG_NIC}-client-${CLIENT_NAME}.conf${NC}"
    fi

    # Restart wireguard to apply changes
    log_info "Restarting WireGuard to apply changes..."
    if command -v wg >/dev/null; then
        if ! wg syncconf "${SERVER_WG_NIC}" <(wg-quick strip "${SERVER_WG_NIC}") 2>/dev/null; then
            log_warn "wg syncconf failed, trying alternative method..."
            systemctl restart "wg-quick@${SERVER_WG_NIC}"
        fi
    else
        systemctl restart "wg-quick@${SERVER_WG_NIC}"
    fi

    echo -e "${GREEN}✅ Client '${CLIENT_NAME}' has been revoked successfully${NC}"
    display_footer
}

# Uninstall WireGuard
function uninstallWg() {
    display_header
    echo -e "${BOLD}${CYAN}=== Uninstall WireGuard ===${NC}\n"

    echo -e "${RED}${BOLD}WARNING: This will completely remove WireGuard and all client configurations!${NC}"
    echo -e "${YELLOW}This action cannot be undone. All VPN connections will be terminated.${NC}"
    echo -e "${YELLOW}If you want to keep your configuration files, please backup /etc/wireguard first.${NC}\n"

    read -rp "Do you want to proceed with uninstallation? [y/N]: " -e REMOVE
    REMOVE=${REMOVE:-N}

    if [[ $REMOVE =~ ^[Yy]$ ]]; then
        checkOS

        log_info "Stopping WireGuard service..."
        systemctl stop "wg-quick@${SERVER_WG_NIC}" 2>/dev/null || true
        systemctl disable "wg-quick@${SERVER_WG_NIC}" 2>/dev/null || true

        log_info "Removing WireGuard packages..."
        if [[ ${OS} == 'ubuntu' || ${OS} == 'debian' ]]; then
            apt-get remove -y wireguard wireguard-tools qrencode || true
        elif [[ ${OS} == 'fedora' ]]; then
            dnf remove -y --noautoremove wireguard-tools qrencode || true
            if [[ ${VERSION_ID} -lt 32 ]]; then
                dnf remove -y --noautoremove wireguard-dkms || true
                dnf copr disable -y jdoss/wireguard || true
            fi
        elif [[ ${OS} == 'centos' || ${OS} == 'almalinux' || ${OS} == 'rocky' ]]; then
            yum remove -y --noautoremove wireguard-tools || true
            if [[ ${VERSION_ID} == 8* ]]; then
                yum remove --noautoremove kmod-wireguard qrencode || true
            fi
        elif [[ ${OS} == 'oracle' ]]; then
            yum remove --noautoremove wireguard-tools qrencode || true
        elif [[ ${OS} == 'arch' ]]; then
            pacman -Rs --noconfirm wireguard-tools qrencode || true
        fi

        log_info "Removing WireGuard configuration files..."
        rm -rf /etc/wireguard || true
        rm -f /etc/sysctl.d/wg.conf || true

        # Reload sysctl
        log_info "Resetting system configuration..."
        sysctl --system

        echo -e "${GREEN}✅ WireGuard has been uninstalled successfully.${NC}"
        exit 0
    else
        echo -e "${YELLOW}Uninstallation canceled.${NC}"
    fi

    display_footer
}

# Management menu
function manageMenu() {
    display_header
    echo -e "${BOLD}${YELLOW}WireGuard VPN Management Console${NC}\n"
    echo -e "${YELLOW}It looks like WireGuard is already installed on this system.${NC}"
    echo -e "${YELLOW}What would you like to do?${NC}\n"

    echo -e "${GREEN}1)${NC} Add a new client"
    echo -e "${GREEN}2)${NC} List all clients"
    echo -e "${GREEN}3)${NC} Revoke a client"
    echo -e "${GREEN}4)${NC} Uninstall WireGuard"
    echo -e "${GREEN}5)${NC} Exit"

    echo ""
    MENU_OPTION=""
    until [[ ${MENU_OPTION} =~ ^[1-5]$ ]]; do
        read -rp "Select an option [1-5]: " MENU_OPTION

        if [[ ! ${MENU_OPTION} =~ ^[1-5]$ ]]; then
            echo -e "${RED}Please select a valid option (1-5)${NC}"
        fi
    done

    case "${MENU_OPTION}" in
        1)
            newClient
            ;;
        2)
            listClients
            ;;
        3)
            revokeClient
            ;;
        4)
            uninstallWg
            ;;
        5)
            echo -e "${GREEN}Exiting...${NC}"
            exit 0
            ;;
    esac

    # Return to menu after function completes
    MENU_OPTION=""
    manageMenu
}

# Main function to start the script
function main() {
    # Initialize variables to prevent errors
    SERVER_WG_NIC=""

    # Load configuration if available
    if [[ -e /etc/wireguard/params ]]; then
        source /etc/wireguard/params
        manageMenu
    else
        # Run initial checks and installation
        initialCheck
        installWireGuard
    fi
}

# Execute main function
main
