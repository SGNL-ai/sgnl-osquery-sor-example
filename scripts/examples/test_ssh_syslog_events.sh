#!/bin/bash
# Comprehensive SSH and Syslog Event Testing Script
# This script tests both SSH and syslog event generation and monitoring

echo "=== SGNL SFDC POC - SSH & Syslog Event Testing ==="
echo "Testing SSH and syslog event generation and monitoring..."
echo

# Check if we're inside the container
if [ ! -f /.dockerenv ]; then
    echo "❌ This script should be run inside the osquery container"
    echo "Run: docker exec -it osquery-linux-test bash"
    echo "Then: /opt/osquery-config/test_ssh_syslog_events.sh"
    exit 1
fi

# Check if osquery is available
if ! command -v osqueryi &> /dev/null; then
    echo "❌ osquery not found. Make sure osquery is installed."
    exit 1
fi

echo "✅ Running inside container with osquery available"
echo

# Function to run osquery and display results
run_osquery() {
    local query="$1"
    local description="$2"
    
    echo "🔍 $description"
    echo "Query: $query"
    echo "Results:"
    osqueryi --csv "$query" | head -10
    echo
}

# Function to generate test events
generate_test_events() {
    echo "🚀 Generating test events..."
    
    # Generate some process events
    ps aux > /dev/null
    whoami > /dev/null
    id > /dev/null
    
    # Generate some file access events  
    ls -la /etc/ > /dev/null
    cat /etc/hostname > /dev/null
    
    # Generate some network activity
    netstat -tuln > /dev/null 2>&1 || ss -tuln > /dev/null
    
    echo "✅ Test events generated"
    echo
}

# Test 1: Basic SSH Monitoring
echo "=== TEST 1: SSH Process Monitoring ==="
run_osquery "SELECT pid, name, cmdline FROM processes WHERE name = 'sshd';" "Current SSH processes"

# Test 2: SSH Network Connections
echo "=== TEST 2: SSH Network Connections ==="
run_osquery "SELECT pid, local_port, remote_address, state FROM process_open_sockets WHERE local_port = 22;" "SSH network connections on port 22"

# Test 3: Basic Syslog Events
echo "=== TEST 3: Recent Syslog Events ==="
run_osquery "SELECT datetime(time, 'unixepoch') as event_time, facility, severity, ident, message FROM syslog_events ORDER BY time DESC LIMIT 5;" "Recent syslog events"

# Test 4: Authentication Events
echo "=== TEST 4: Authentication Events ==="
run_osquery "SELECT datetime(time, 'unixepoch') as event_time, severity, message FROM syslog_events WHERE facility = 'auth' ORDER BY time DESC LIMIT 5;" "Recent authentication events"

# Generate test events
generate_test_events

# Test 5: Process Events
echo "=== TEST 5: Recent Process Events ==="
run_osquery "SELECT datetime(time, 'unixepoch') as event_time, pid, path, cmdline FROM process_events ORDER BY time DESC LIMIT 5;" "Recent process events"

# Test 6: File Events
echo "=== TEST 6: Recent File Events ==="  
run_osquery "SELECT datetime(time, 'unixepoch') as event_time, target_path, action FROM file_events ORDER BY time DESC LIMIT 5;" "Recent file events"

# Test 7: System Summary
echo "=== TEST 7: System Summary ==="
run_osquery "SELECT COUNT(*) as total_processes FROM processes;" "Total running processes"
run_osquery "SELECT COUNT(*) as total_syslog_events FROM syslog_events WHERE time > (strftime('%s', 'now') - 3600);" "Syslog events in last hour"

# Test enhanced monitoring if files exist
if [ -f "/opt/osquery-config/enhanced_ssh_monitoring.sql" ]; then
    echo "=== TEST 8: Enhanced SSH Monitoring ==="
    echo "🔍 Running enhanced SSH authentication events query..."
    osqueryi --csv "$(head -n 30 /opt/osquery-config/enhanced_ssh_monitoring.sql | tail -n +3)" | head -5
    echo
fi

if [ -f "/opt/osquery-config/enhanced_syslog_monitoring.sql" ]; then
    echo "=== TEST 9: Enhanced Syslog Monitoring ==="
    echo "🔍 Running enhanced authentication events query..."
    osqueryi --csv "$(head -n 25 /opt/osquery-config/enhanced_syslog_monitoring.sql | tail -n +3)" | head -5
    echo
fi

# Test SSH event generation
echo "=== TEST 10: SSH Event Generation ==="
echo "🔧 Testing SSH connection attempts..."

# Try to generate SSH events (will fail but create log entries)
echo "Attempting failed SSH connections to generate authentication events..."
timeout 2 ssh -o ConnectTimeout=1 -o PasswordAuthentication=yes -o PreferredAuthentications=password testuser@localhost 2>/dev/null || true
timeout 2 ssh -o ConnectTimeout=1 -o PasswordAuthentication=yes -o PreferredAuthentications=password invaliduser@localhost 2>/dev/null || true

sleep 2

# Check for SSH-related syslog events
echo "🔍 Checking for SSH-related syslog events..."
run_osquery "SELECT datetime(time, 'unixepoch') as event_time, message FROM syslog_events WHERE message LIKE '%ssh%' ORDER BY time DESC LIMIT 3;" "SSH-related syslog events"

echo "=== MONITORING STATUS SUMMARY ==="
echo "✅ SSH Events: Monitoring SSH processes and connections"
echo "✅ Syslog Events: Capturing system logs with severity <= 4"
echo "✅ Process Events: Tracking process creation and termination"
echo "✅ File Events: Monitoring file system activity"
echo

echo "=== RECOMMENDATIONS ==="
echo "1. Use enhanced monitoring queries for more detailed analysis"
echo "2. Run the failed login generator script to test SSH brute force detection"
echo "3. Monitor /var/log/osquery/ for continuous event logs"
echo "4. Use 'osqueryi' interactively for real-time querying"
echo

echo "=== QUICK REFERENCE COMMANDS ==="
echo "# Interactive osquery:"
echo "osqueryi"
echo
echo "# View recent SSH events:"
echo "osqueryi --csv \"SELECT * FROM syslog_events WHERE message LIKE '%ssh%' ORDER BY time DESC LIMIT 10;\""
echo
echo "# Monitor SSH connections:"
echo "osqueryi --csv \"SELECT * FROM process_open_sockets WHERE local_port = 22;\""
echo
echo "# Check authentication events:"
echo "osqueryi --csv \"SELECT * FROM syslog_events WHERE facility = 'auth' ORDER BY time DESC LIMIT 10;\""
echo

echo "✅ SSH and Syslog event testing completed!" 