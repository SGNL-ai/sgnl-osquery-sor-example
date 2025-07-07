



# Start the service
docker-compose up -d

# Access the container
docker exec -it osquery-linux-test bash

# Use osquery interactively
osqueryi

# Test AWS commands
aws sts get-caller-identity
aws ec2 describe-instances
aws s3 ls

-------
Using security_testing_script.sh you can run the following osquery:

```
WITH user_incidents AS (
    -- Suspicious files
    SELECT 
        'suspicious_file' as incident_type,
        u.username,
        f.path as details,
        datetime(f.ctime, 'unixepoch') as timestamp
    FROM file f
    JOIN users u ON f.uid = u.uid
    WHERE f.path LIKE '/tmp/%' 
      AND (f.filename LIKE '.%' OR f.filename LIKE '%suspicious%')
      AND f.ctime > (strftime('%s', 'now') - 3600)
    
    UNION ALL
    
    -- Suspicious processes
    SELECT 
        'suspicious_process' as incident_type,
        u.username,
        p.name || ': ' || p.cmdline as details,
        datetime(p.start_time, 'unixepoch') as timestamp
    FROM processes p
    JOIN users u ON p.uid = u.uid
    WHERE p.name IN ('svchost', 'nc', 'nmap')
       OR p.path LIKE '/tmp/%'
       OR p.cmdline LIKE '%python3 -m http.server%'
    
    UNION ALL
    
    -- Network connections
    SELECT 
        'network_connection' as incident_type,
        u.username,
        pos.local_address || ':' || pos.local_port || ' -> ' || pos.remote_address || ':' || pos.remote_port as details,
        datetime('now') as timestamp
    FROM process_open_sockets pos
    JOIN processes p ON pos.pid = p.pid
    JOIN users u ON p.uid = u.uid
    WHERE pos.remote_port IN (4444, 1337, 8080, 9999)
       OR pos.local_port > 8000
)
SELECT 
    incident_type,
    username,
    details,
    timestamp
FROM user_incidents
ORDER BY timestamp DESC;
```

With S3 Bucket export

```
sudo osqueryi --csv --separator "," "WITH user_incidents AS (
    -- Suspicious files
    SELECT 
        'suspicious_file' as incident_type,
        u.username,
        f.path as details,
        datetime(f.ctime, 'unixepoch') as timestamp
    FROM file f
    JOIN users u ON f.uid = u.uid
    WHERE f.path LIKE '/tmp/%' 
      AND (f.filename LIKE '.%' OR f.filename LIKE '%suspicious%')
      AND f.ctime > (strftime('%s', 'now') - 3600)
    
    UNION ALL
    
    -- Suspicious processes
    SELECT 
        'suspicious_process' as incident_type,
        u.username,
        p.name || ': ' || p.cmdline as details,
        datetime(p.start_time, 'unixepoch') as timestamp
    FROM processes p
    JOIN users u ON p.uid = u.uid
    WHERE p.name IN ('svchost', 'nc', 'nmap')
       OR p.path LIKE '/tmp/%'
       OR p.cmdline LIKE '%python3 -m http.server%'
    
    UNION ALL
    
    -- Network connections
    SELECT 
        'network_connection' as incident_type,
        u.username,
        pos.local_address || ':' || pos.local_port || ' -> ' || pos.remote_address || ':' || pos.remote_port as details,
        datetime('now') as timestamp
    FROM process_open_sockets pos
    JOIN processes p ON pos.pid = p.pid
    JOIN users u ON p.uid = u.uid
    WHERE pos.remote_port IN (4444, 1337, 8080, 9999)
       OR pos.local_port > 8000
)
SELECT 
    incident_type,
    username,
    details,
    timestamp
FROM user_incidents
ORDER BY timestamp DESC;"| aws s3 cp - s3://sgnl-se-s3-bucket-sandbox/linux_incidents.csv
```
Sample output:
+--------------------+------------+--------------------------------------+---------------------+
| incident_type      | username   | details                              | timestamp           |
+--------------------+------------+--------------------------------------+---------------------+
| network_connection | lisa.galia | 0.0.0.0:8888 -> 0.0.0.0:0            | 2025-07-07 01:59:13 |
| network_connection | root       | 127.0.0.1:32813 -> 0.0.0.0:0         | 2025-07-07 01:59:13 |
| suspicious_process | lisa.galia | python3: python3 -m http.server 8888 | 2025-07-07 01:11:04 |
+--------------------+------------+--------------------------------------+---------------------+

Another example:
-- Enhanced user incident detection with hostname and IP address

```
sudo osqueryi --csv --separator "," "WITH system_context AS (
    -- Get hostname
    SELECT hostname FROM system_info LIMIT 1
), 
network_context AS (
    -- Get primary IP address (excluding loopback)
    SELECT address as ip_address 
    FROM interface_addresses 
    WHERE interface != 'lo' 
      AND address NOT LIKE '127.%'
      AND address NOT LIKE '169.254.%'  -- Exclude APIPA
      AND address NOT LIKE 'fe80:%'     -- Exclude link-local IPv6
    ORDER BY interface 
    LIMIT 1
),
user_incidents AS (
    -- Suspicious files
    SELECT 
        'suspicious_file' as incident_type,
        u.username,
        f.path as details,
        datetime(f.ctime, 'unixepoch') as timestamp
    FROM file f
    JOIN users u ON f.uid = u.uid
    WHERE f.path LIKE '/tmp/%' 
      AND (f.filename LIKE '.%' OR f.filename LIKE '%suspicious%')
      AND f.ctime > (strftime('%s', 'now') - 3600)
    
    UNION ALL
    
    -- Suspicious processes
    SELECT 
        'suspicious_process' as incident_type,
        u.username,
        p.name || ': ' || p.cmdline as details,
        datetime(p.start_time, 'unixepoch') as timestamp
    FROM processes p
    JOIN users u ON p.uid = u.uid
    WHERE p.name IN ('svchost', 'nc', 'nmap')
       OR p.path LIKE '/tmp/%'
       OR p.cmdline LIKE '%python3 -m http.server%'
    
    UNION ALL
    
    -- Network connections
    SELECT 
        'network_connection' as incident_type,
        u.username,
        pos.local_address || ':' || pos.local_port || ' -> ' || pos.remote_address || ':' || pos.remote_port as details,
        datetime('now') as timestamp
    FROM process_open_sockets pos
    JOIN processes p ON pos.pid = p.pid
    JOIN users u ON p.uid = u.uid
    WHERE pos.remote_port IN (4444, 1337, 8080, 9999)
       OR pos.local_port > 8000
)
SELECT 
    printf('%s-%08d', 
           strftime('%Y%m%d%H%M%S', 'now'), 
           abs(random())
    ) as incident_id,
    sc.hostname,
    nc.ip_address,
    ui.incident_type,
    ui.username,
    ui.details,
    ui.timestamp
FROM user_incidents ui
CROSS JOIN system_context sc
CROSS JOIN network_context nc
ORDER BY ui.timestamp DESC;" | aws s3 cp - s3://sgnl-se-s3-bucket-sandbox/linux_incidents.csv
```

Sample output



