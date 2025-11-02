#!/usr/bin/env python3
import re
import psycopg2
from datetime import datetime
import sys
import os

# Connection parameters
conn_params = {
    'host': os.getenv('PGHOST', 'postgres'),
    'database': os.getenv('PGDATABASE', 'logdb'),
    'user': os.getenv('PGUSER', 'loguser'),
    'password': os.getenv('PGPASSWORD', 'logpass'),
    'port': int(os.getenv('PGPORT', '5432')),
}

# Regex patterns
SYSLOG_PATTERN = re.compile(
    r'^(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>\S+)\s+(?P<hostname>\S+)\s+'
    r'(?P<program>\w+)(?:\[(?P<pid>\d+)\])?: (?P<message>.+)$'
)

FAILED_PASSWORD_PATTERN = re.compile(
    r'Failed password for (invalid user )?(?P<username>\S+) from '
    r'(?P<ip>\S+) port (?P<port>\d+)'
)

AUTH_FAILURE_PATTERN = re.compile(
    r'authentication failure;.*rhost=(?P<ip>\S+)(\s+user=(?P<username>\S+))?'
)

INVALID_USER_PATTERN = re.compile(
    r'Invalid user (?P<username>\S+) from (?P<ip>\S+) port (?P<port>\d+)'
)

def parse_log_line(line):
    """Parse a single log line and extract relevant information."""
    match = SYSLOG_PATTERN.match(line)
    if not match:
        return None

    data = match.groupdict()

    # Parse timestamp (add current year as syslog doesn't include it)
    current_year = datetime.now().year
    timestamp_str = f"{data['month']} {data['day']} {data['time']} {current_year}"
    try:
        timestamp = datetime.strptime(timestamp_str, '%b %d %H:%M:%S %Y')
    except ValueError:
        return None

    message = data['message']
    event_type = None
    username = None
    source_ip = None
    port = None

    # Try to match different event types
    if 'Failed password' in message:
        match = FAILED_PASSWORD_PATTERN.search(message)
        if match:
            event_type = 'failed_password'
            username = match.group('username')
            source_ip = match.group('ip')
            port = int(match.group('port'))

    elif 'authentication failure' in message:
        match = AUTH_FAILURE_PATTERN.search(message)
        if match:
            event_type = 'auth_failure'
            source_ip = match.group('ip')
            username = match.group('username')

    elif 'Invalid user' in message:
        match = INVALID_USER_PATTERN.search(message)
        if match:
            event_type = 'invalid_user'
            username = match.group('username')
            source_ip = match.group('ip')
            port = int(match.group('port'))

    if not source_ip:
        return None

    return {
        'timestamp': timestamp,
        'hostname': data['hostname'],
        'program': data['program'],
        'pid': int(data['pid']) if data['pid'] else None,
        'log_message': message,
        'event_type': event_type,
        'username': username,
        'source_ip': source_ip,
        'port': port
    }

def import_logs(log_file_path):
    """Import logs from file into PostgreSQL."""
    conn = psycopg2.connect(**conn_params)
    cur = conn.cursor()

    insert_query = """
        INSERT INTO auth_logs
        (timestamp, hostname, program, pid, log_message, event_type,
         username, source_ip, port)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
    """

    processed = 0
    inserted = 0

    with open(log_file_path, 'r') as f:
        for line in f:
            processed += 1
            parsed = parse_log_line(line.strip())

            if parsed:
                try:
                    cur.execute(insert_query, (
                        parsed['timestamp'],
                        parsed['hostname'],
                        parsed['program'],
                        parsed['pid'],
                        parsed['log_message'],
                        parsed['event_type'],
                        parsed['username'],
                        parsed['source_ip'],
                        parsed['port']
                    ))
                    inserted += 1

                    if inserted % 1000 == 0:
                        conn.commit()
                        print(f"Processed: {processed}, Inserted: {inserted}", end='\r')

                except Exception as e:
                    print(f"\nError inserting record: {e}")
                    print(f"Data: {parsed}")
                    conn.rollback()

    conn.commit()

    # Refresh materialized view
    print("\nRefreshing materialized view...")
    cur.execute("REFRESH MATERIALIZED VIEW auth_logs_with_geoip;")
    conn.commit()

    cur.close()
    conn.close()

    print(f"\n\nImport complete!")
    print(f"Total lines processed: {processed}")
    print(f"Total records inserted: {inserted}")

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <path_to_auth.log>")
        sys.exit(1)

    import_logs(sys.argv[1])
