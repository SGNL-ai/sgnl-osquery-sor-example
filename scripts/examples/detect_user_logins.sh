#!/bin/bash

# User-Based Failed Login Detection Script
# Analyzes btmp file for sequential failed login attempts by user

echo "=== User-Based Failed Login Detection ==="
echo "Timestamp: $(date)"
echo

# 1. Show all failed login attempts
echo "--- All Failed Login Attempts ---"
utmpdump /var/log/btmp 2>/dev/null | while read line; do
    if [[ $line =~ \[6\].*\].*\[([^]]+)\].*\[ssh:notty.*\[(.*)\].*\[([0-9-]+T[0-9:,+]+)\] ]]; then
        username="${BASH_REMATCH[1]}"
        ip="${BASH_REMATCH[2]}"
        timestamp="${BASH_REMATCH[3]}"
        echo "FAILED LOGIN: User=$username, IP=$ip, Time=$timestamp"
    fi
done
echo

# 2. Count failed attempts by user
echo "--- Failed Attempts Count by User ---"
utmpdump /var/log/btmp 2>/dev/null | grep -oP '\[6\][^[]*\[[^[]*\[\K[^]]+' | sort | uniq -c | sort -nr
echo

# 3. Detect brute force attempts (3+ failures)
echo "--- Potential Brute Force Attacks (3+ attempts) ---"
temp_file="/tmp/failed_logins.tmp"
utmpdump /var/log/btmp 2>/dev/null > "$temp_file"

while read line; do
    if [[ $line =~ \[6\].*\].*\[([^]]+)\].*\[ssh:notty.*\[(.*)\].*\[([0-9-]+T[0-9:,+]+)\] ]]; then
        username="${BASH_REMATCH[1]}"
        ip="${BASH_REMATCH[2]}"
        timestamp="${BASH_REMATCH[3]}"
        echo "$username|$ip|$timestamp"
    fi
done < "$temp_file" | sort | uniq -c | while read count data; do
    if [ "$count" -ge 3 ]; then
        user=$(echo "$data" | cut -d'|' -f1)
        ip=$(echo "$data" | cut -d'|' -f2)
        echo "ALERT: User '$user' from IP '$ip' has $count failed login attempts"
    fi
done

rm -f "$temp_file"
echo

# 4. Recent failed attempts (last 10)
echo "--- Recent Failed Login Attempts (Last 10) ---"
utmpdump /var/log/btmp 2>/dev/null | tail -10 | while read line; do
    if [[ $line =~ \[6\].*\].*\[([^]]+)\].*\[ssh:notty.*\[(.*)\].*\[([0-9-]+T[0-9:,+]+)\] ]]; then
        username="${BASH_REMATCH[1]}"
        ip="${BASH_REMATCH[2]}"
        timestamp="${BASH_REMATCH[3]}"
        echo "User: $username | IP: $ip | Time: $timestamp"
    fi
done

echo "=== Detection Complete ===" 