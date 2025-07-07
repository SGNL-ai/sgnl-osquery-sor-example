#!/bin/bash
# save as generate_failed_logins.sh

# echo "Generating failed login attempts..."

# # SSH attempts
# for i in {1..15}; do
#     echo "Attempt $i"
#     timeout 5 ssh -o ConnectTimeout=1 -o PasswordAuthentication=yes lisa.galia$i@localhost -p 2222 2>/dev/null || true
#     sleep 2
# done

# echo "Waiting for logs to populate..."

echo "=== Generating Failed Login Test Data ==="

# Generate failed SSH attempts for multiple users
users=("lisa.galia" "admin")

for user in "${users[@]}"; do
    echo "Generating 6+ failed attempts for $user..."
    for i in {1..7}; do
        timeout 2 ssh -o ConnectTimeout=1 -o PasswordAuthentication=yes -o PreferredAuthentications=password "$user@localhost" 2>/dev/null || true
        sleep 0.5
    done
done

echo "Waiting 10 seconds for logs to populate..."
sleep 10

echo "=== Querying Failed Logins ==="