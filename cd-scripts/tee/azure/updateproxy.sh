#!/bin/bash

# Variables (Update these as needed)x
CADDYFILE=${1:-/etc/caddy/Caddyfile}  # Path to your Caddyfile
GIT_COMMIT_HASH=${2:-dev}
BASE_PORT=6061                      # The starting port for your reverse_proxy directives

# Function to check if handle_path for the given commit hash exists
handle_path_exists() {
    local commit_hash=$1
    grep -q "handle_path /${commit_hash}\*" "$CADDYFILE"
}

# Function to extract the port for a given commit hash
extract_port_for_commit() {
    local commit_hash=$1
    grep -Pzo "handle_path /${commit_hash}\* \{\n\s*reverse_proxy :(.*) " "$CADDYFILE" | grep -Po "reverse_proxy :(.*) " | awk '{print $2}'
}

# Function to get the last port in the Caddyfile
get_last_port() {
    grep -Po "reverse_proxy :([0-9]+)" "$CADDYFILE" | awk -F: '{print $2}' | sort -n | tail -1
}

# Function to add a new handle_path block with incremented port inside notary.codes block
add_new_handle_path() {
    local new_port=$1
    local commit_hash=$2

    # Use a temporary file for inserting the handle_path block
    tmp_file=$(mktemp)

    # Add the new handle_path in the notary.codes block
    awk -v port="$new_port" -v hash="$commit_hash" '
        /tee\.notary\.codes \{/ {
            print; 
            print "    handle_path /" hash "* {";
            print "        reverse_proxy :" port " :3333 tlsnotary.org:443 {";
            print "            lb_try_duration 4s";
            print "            fail_duration 10s";
            print "            lb_policy header X-Upstream {";
            print "                fallback first";
            print "            }";
            print "        }";
            print "    }";
            next;
        }
        { print }
    ' "$CADDYFILE" > "$tmp_file"

    # Overwrite the original Caddyfile with the updated content
    mv "$tmp_file" "$CADDYFILE"

    echo "Added new handle_path for $commit_hash with port :$new_port inside notary.codes"
}

# Check if the commit hash already exists in a handle_path
if handle_path_exists "$GIT_COMMIT_HASH"; then
    existing_port=$(extract_port_for_commit "$GIT_COMMIT_HASH")
    echo "Commit hash $GIT_COMMIT_HASH already exists with port :$existing_port"
    exit 0
else
    echo "Commit hash $GIT_COMMIT_HASH does not exist, adding a new handle_path..."
    # Get the last port used and increment it
    last_port=$(get_last_port)
    if [[ -z "$last_port" ]]; then
        last_port=$BASE_PORT
    fi
    new_port=$((last_port + 1))

    # Add the new handle_path block inside notary.codes block
    add_new_handle_path "$new_port" "$GIT_COMMIT_HASH"
fi
