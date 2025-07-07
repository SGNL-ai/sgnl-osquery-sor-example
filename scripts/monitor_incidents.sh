#!/bin/bash

# Incident Monitoring Script
# Usage: ./monitor_incidents.sh [username]

TARGET_USER=${1:-"lisa.galia"}
LOGFILE="/tmp/incident_monitor.log"

echo "Starting incident monitoring for user: $TARGET_USER"
echo "Logs will be written to: $LOGFILE"
echo "Press Ctrl+C to stop monitoring"

# Create log file header
echo "$(date): Starting incident monitoring for user $TARGET_USER" >> $LOGFILE

while true; do
    # Query for suspicious processes
    INCIDENTS=$(sudo osqueryi --json "
        SELECT 
            p.pid,
            p.name,
            p.cmdline,
            p.cwd,
            p.uid,
            u.username,
            p.parent,
            datetime(p.start_time, 'unixepoch') as start_time
        FROM processes p
        JOIN users u ON p.uid = u.uid
        WHERE u.username = '$TARGET_USER'
           OR p.cmdline LIKE '%python3 -m http.server%'
           OR p.cmdline LIKE '%find /home%'
           OR p.cmdline LIKE '%cat /etc/passwd%'
           OR p.cmdline LIKE '%whoami%'
           OR p.name IN ('sleep', 'nc', 'nmap', 'curl')
        ORDER BY p.start_time DESC;
    ")
    
    # Check if any incidents found
    if [[ $(echo "$INCIDENTS" | jq length) -gt 0 ]]; then
        echo "$(date): INCIDENT DETECTED!"
        echo "$INCIDENTS" | jq -r '.[] | "PID: \(.pid) | Process: \(.name) | User: \(.username) | Command: \(.cmdline) | Start: \(.start_time)"'
        echo "$(date): $INCIDENTS" >> $LOGFILE
        
        # Send alert (you can customize this)
        echo "ALERT: Suspicious process detected for user $TARGET_USER" | logger -t IncidentMonitor
    fi
    
    sleep 30  # Check every 30 seconds
done 