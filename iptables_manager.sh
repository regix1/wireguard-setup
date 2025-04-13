#!/bin/bash
#
# IP Ban Manager (IPv4 Only)
# A lightweight tool for managing IPv4 bans via iptables
#
# Usage: sudo ./ipban.sh

# Configuration
BANNED_CHAIN="BANNED_IPS"
VERSION="1.4"
RULES_FILE="/etc/wireguard/banned_ips.txt"

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

# Save banned IPs to simple text file (NOT iptables-save format)
save_rules() {
    log_info "Saving banned IPs to $RULES_FILE..."

    # Make sure the directory exists
    mkdir -p $(dirname "$RULES_FILE")

    # Clear the file first
    > "$RULES_FILE"

    # Extract each banned IP and its comment and save to file
    iptables -L "$BANNED_CHAIN" -n | grep DROP | while read -r line; do
        ip=$(echo "$line" | awk '{print $4}')
        comment=$(echo "$line" | grep -o "\/\*.*\*\/" | sed 's/\/\*//;s/\*\///')

        if [ -n "$comment" ]; then
            echo "$ip|$comment" >> "$RULES_FILE"
        else
            echo "$ip" >> "$RULES_FILE"
        fi
    done

    log_info "Banned IPs saved successfully"
}

# Function to validate IPv4 address
validate_ip() {
    local ip=$1

    if [[ -z "$ip" ]]; then
        log_error "IP address cannot be empty"
        return 1
    fi

    # Check for CIDR notation
    if [[ "$ip" == *"/"* ]]; then
        local cidr=${ip#*/}
        ip=${ip%/*}

        # Validate CIDR
        if ! [[ "$cidr" =~ ^[0-9]+$ ]] || [ "$cidr" -lt 0 ] || [ "$cidr" -gt 32 ]; then
            log_error "Invalid CIDR notation: /$cidr (must be 0-32)"
            return 1
        fi
    fi

    # Basic IPv4 format validation
    if ! [[ $ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        log_error "Invalid IP address format: $ip"
        return 1
    fi

    # Validate each octet
    IFS='.' read -r -a octets <<< "$ip"
    for octet in "${octets[@]}"; do
        if [[ "$octet" -gt 255 ]]; then
            log_error "Invalid IP address (octet > 255): $ip"
            return 1
        fi
    done

    return 0
}

# Function to ensure the BANNED_IPS chain exists
ensure_banned_chain() {
    if ! iptables -L "$BANNED_CHAIN" &>/dev/null; then
        log_info "Creating $BANNED_CHAIN chain..."
        iptables -N "$BANNED_CHAIN"

        # Check if chain exists in INPUT and FORWARD
        if ! iptables -C INPUT -j "$BANNED_CHAIN" 2>/dev/null; then
            iptables -I INPUT 1 -j "$BANNED_CHAIN"
        fi

        if ! iptables -C FORWARD -j "$BANNED_CHAIN" 2>/dev/null; then
            iptables -I FORWARD 1 -j "$BANNED_CHAIN"
        fi

        log_info "$BANNED_CHAIN chain created and linked to INPUT and FORWARD chains"
    fi
}

# Function to ban an IP
ban_ip() {
    display_header
    echo -e "${BOLD}${CYAN}=== Ban an IP Address ===${NC}\n"

    # Show current bans first
    local current_bans=$(iptables -L "$BANNED_CHAIN" -n 2>/dev/null | grep DROP | grep -E '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | awk '{print $4}' | sort | uniq)

    if [ -n "$current_bans" ]; then
        echo -e "${BOLD}${YELLOW}Currently Banned IPs:${NC}"
        echo -e "${YELLOW}------------------------------------------${NC}"
        while IFS= read -r ip; do
            local comment=$(iptables -L "$BANNED_CHAIN" -n | grep "$ip" | grep -o "\/\*.*\*\/" | sed 's/\/\*//;s/\*\///' | head -n 1)
            if [ -n "$comment" ]; then
                echo -e "${RED}BANNED:${NC} $ip ${PURPLE}($comment)${NC}"
            else
                echo -e "${RED}BANNED:${NC} $ip"
            fi
        done <<< "$current_bans"
        echo
    fi

    while true; do
        echo -e "${YELLOW}Enter the IP address or CIDR range to ban (or 'q' to return to menu):${NC}"
        read -r ip_to_ban

        # Allow returning to menu
        if [[ "$ip_to_ban" == "q" || "$ip_to_ban" == "Q" ]]; then
            return 0
        fi

        # Check for empty input
        if [[ -z "$ip_to_ban" ]]; then
            log_error "IP address cannot be empty. Please try again or enter 'q' to cancel."
            continue
        fi

        # Validate IP
        if ! validate_ip "$ip_to_ban"; then
            log_error "Invalid IP address format. Please try again."
            continue
        fi

        break
    done

    ensure_banned_chain

    # Check if this IP already has a ban rule
    if echo "$current_bans" | grep -q "$ip_to_ban"; then
        log_warn "IP $ip_to_ban is already banned"

        # Get current comment if any
        current_comment=$(iptables -L "$BANNED_CHAIN" -n | grep "$ip_to_ban" | grep -o "\/\*.*\*\/" | sed 's/\/\*//;s/\*\///' | head -n 1)
        if [[ -n "$current_comment" ]]; then
            log_info "Current ban reason: $current_comment"
        fi

        # Ask if user wants to change the comment
        if prompt_yes_no "Do you want to change the ban reason?" "n"; then
            # Get new comment
            echo -e "\n${YELLOW}Enter new reason for this ban:${NC}"
            read -r new_ban_reason

            # Find and remove rules for the IP
            rule_nums=$(iptables -L "$BANNED_CHAIN" --line-numbers -n | grep "$ip_to_ban" | grep "DROP" | awk '{print $1}' | sort -nr)
            if [ -n "$rule_nums" ]; then
                while IFS= read -r num; do
                    iptables -D "$BANNED_CHAIN" "$num"
                done <<< "$rule_nums"
            fi

            # Add new rule with updated comment
            if [[ -n "$new_ban_reason" ]]; then
                iptables -A "$BANNED_CHAIN" -s "$ip_to_ban" -m comment --comment "$new_ban_reason" -j DROP
                log_info "Updated ban reason for IP: $ip_to_ban"
            else
                iptables -A "$BANNED_CHAIN" -s "$ip_to_ban" -j DROP
                log_info "Removed ban reason for IP: $ip_to_ban"
            fi

            # Save changes
            save_rules
        fi
    else
        # Get optional comment
        echo -e "\n${YELLOW}Enter a reason for this ban (optional):${NC}"
        read -r ban_reason

        log_info "Adding ban for $ip_to_ban to IPTables..."

        # Add ban rule to BANNED_IPS chain
        if [[ -n "$ban_reason" ]]; then
            iptables -A "$BANNED_CHAIN" -s "$ip_to_ban" -m comment --comment "$ban_reason" -j DROP
        else
            iptables -A "$BANNED_CHAIN" -s "$ip_to_ban" -j DROP
        fi
        log_info "Added ban for IP: $ip_to_ban"

        # Save changes
        save_rules
    fi

    display_footer
}

# Function to list current bans
list_bans() {
    display_header
    echo -e "${BOLD}${CYAN}=== Banned IP Addresses ===${NC}\n"

    ensure_banned_chain

    # Get banned IPs from BANNED_IPS chain
    banned_ips=$(iptables -L "$BANNED_CHAIN" -n | grep DROP)

    if [ -n "$banned_ips" ]; then
        echo -e "${BOLD}${YELLOW}Currently Banned IPs:${NC}"
        echo -e "${YELLOW}------------------------------------------${NC}"

        while IFS= read -r line; do
            local ip=$(echo "$line" | awk '{print $4}')
            local comment=$(echo "$line" | grep -o "\/\*.*\*\/" | sed 's/\/\*//;s/\*\///')

            if [ -n "$comment" ]; then
                echo -e "${RED}BANNED:${NC} $ip ${PURPLE}($comment)${NC}"
            else
                echo -e "${RED}BANNED:${NC} $ip"
            fi
        done <<< "$banned_ips"

        # Count total bans
        ban_count=$(echo "$banned_ips" | wc -l)
        echo
        log_info "Total banned IPs: $ban_count"
    else
        log_info "No banned IPs found"
    fi

    display_footer
}

# Function to debug banned IPs (detailed view)
debug_banned_ips() {
    display_header
    echo -e "${BOLD}${CYAN}=== Debug Banned IP Rules (Detailed) ===${NC}\n"

    ensure_banned_chain

    # Get all rules from the BANNED_CHAIN
    local rules=$(iptables -L "$BANNED_CHAIN" -n --line-numbers -v)

    if [ -z "$(echo "$rules" | grep DROP)" ]; then
        log_info "No banned IPs found"
        display_footer
        return 0
    fi

    echo -e "${BOLD}${YELLOW}Detailed Rules in $BANNED_CHAIN chain:${NC}"
    echo -e "${YELLOW}------------------------------------------${NC}"

    # Add table header with column descriptions
    echo -e "${CYAN}Rule#  Packets  Bytes  Action  Proto  Opt  In  Out  Source IP          Destination     Comments${NC}"
    echo -e "${CYAN}-----  -------  -----  ------  -----  ---  --  ---  ---------------   ------------    --------${NC}"

    # Skip the first two header lines and show the rest
    echo "$rules" | tail -n +3

    display_footer
}

# Function to unban an IP
unban_ip() {
    display_header
    echo -e "${BOLD}${CYAN}=== Unban an IP Address ===${NC}\n"

    ensure_banned_chain

    # Get banned IPs from BANNED_IPS chain
    banned_ips=$(iptables -L "$BANNED_CHAIN" -n | grep DROP | grep -E '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | awk '{print $4}' | sort | uniq)

    if [ -z "$banned_ips" ]; then
        log_info "No banned IPs found to unban"
        display_footer
        return 0
    fi

    # Create array of IPs
    mapfile -t ip_array <<< "$banned_ips"

    # Display list with numbers
    echo -e "${BOLD}${YELLOW}Select an IP to unban:${NC}"
    echo -e "${YELLOW}------------------------------------------${NC}"
    for i in "${!ip_array[@]}"; do
        ip="${ip_array[$i]}"
        comment=$(iptables -L "$BANNED_CHAIN" -n | grep "$ip" | grep -o "\/\*.*\*\/" | sed 's/\/\*//;s/\*\///' | head -n 1)

        if [ -n "$comment" ]; then
            echo -e "${GREEN}$((i+1))${NC}) ${YELLOW}$ip${NC} ${PURPLE}($comment)${NC}"
        else
            echo -e "${GREEN}$((i+1))${NC}) ${YELLOW}$ip${NC}"
        fi
    done

    echo -e "\n${GREEN}0${NC}) Cancel"
    echo

    echo -e "${CYAN}Enter the number of the IP to unban [0-${#ip_array[@]}]:${NC} "
    read -r selection

    # Validate selection
    if [[ ! "$selection" =~ ^[0-9]+$ ]]; then
        log_error "Invalid input. Please enter a number."
        display_footer
        return 1
    fi

    if [ "$selection" -eq 0 ]; then
        log_info "Unban canceled"
        display_footer
        return 0
    fi

    if [ "$selection" -gt "${#ip_array[@]}" ] || [ "$selection" -lt 1 ]; then
        log_error "Invalid selection. Please choose a number between 1 and ${#ip_array[@]}."
        display_footer
        return 1
    fi

    # Get the selected IP
    selected_ip="${ip_array[$((selection-1))]}"

    log_info "Removing ban for $selected_ip..."

    # Find and remove rules for the selected IP with any comment
    local count=0

    # Get rule numbers in reverse order (to delete safely)
    rule_nums=$(iptables -L "$BANNED_CHAIN" --line-numbers -n | grep -E "\s+$selected_ip\s+" | awk '{print $1}' | sort -nr)

    if [ -n "$rule_nums" ]; then
        while IFS= read -r num; do
            iptables -D "$BANNED_CHAIN" "$num"
            count=$((count + 1))
        done <<< "$rule_nums"
    fi

    if [ $count -gt 0 ]; then
        log_info "Successfully removed $count rules for IP: $selected_ip"

        # Save changes
        save_rules
    else
        log_warn "No rules were found for IP: $selected_ip"
    fi

    display_footer
}

# Function to remove all bans
clear_all_bans() {
    display_header
    echo -e "${BOLD}${CYAN}=== Clear All Bans ===${NC}\n"

    ensure_banned_chain

    echo -e "${RED}${BOLD}WARNING: This will remove all IP bans.${NC}"
    if ! prompt_yes_no "Are you sure you want to continue?"; then
        log_info "Operation canceled"
        display_footer
        return 0
    fi

    log_info "Flushing all bans from $BANNED_CHAIN chain..."
    iptables -F "$BANNED_CHAIN"

    # Save changes
    save_rules

    log_info "All bans have been removed"

    display_footer
}

# Display functions
display_header() {
    printf "\033c" # Clear screen
    echo -e "${BLUE}${BOLD}===============================================${NC}"
    echo -e "${BLUE}${BOLD}       IP Ban Manager v${VERSION}       ${NC}"
    echo -e "${BLUE}${BOLD}===============================================${NC}"
    echo
}

display_footer() {
    echo
    echo -e "${BOLD}Press Enter to continue...${NC}"
    read -r
}

# Interactive menu
show_menu() {
    display_header

    echo -e "${BOLD}${YELLOW}╔════════════════════════════════════════╗${NC}"
    echo -e "${BOLD}${YELLOW}║            SELECT AN OPTION            ║${NC}"
    echo -e "${BOLD}${YELLOW}╚════════════════════════════════════════╝${NC}"
    echo
    echo -e "${GREEN}1)${NC} Ban an IP address"
    echo -e "${GREEN}2)${NC} Unban an IP address"
    echo -e "${GREEN}3)${NC} List banned IPs"
    echo -e "${GREEN}4)${NC} Clear all bans"
    echo -e "${GREEN}5)${NC} Debug banned IP rules (detailed view)"
    echo -e "${GREEN}6)${NC} Exit"
    echo
    echo -n -e "${CYAN}Enter option [1-6]:${NC} "
}

# Main script execution
main() {
    # Ensure banned chain exists
    ensure_banned_chain

    # Initial message
    log_info "IP Ban Manager started successfully"

    # Main menu loop
    while true; do
        show_menu
        read -r choice

        case $choice in
            1) ban_ip ;;
            2) unban_ip ;;
            3) list_bans ;;
            4) clear_all_bans ;;
            5) debug_banned_ips ;;
            6)
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
