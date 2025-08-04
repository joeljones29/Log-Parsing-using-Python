#for parsing through auth.log to detect for SSH brute force attacks
import re

success_pattern = re.compile(r'(^\S+).*Accepted password for (\S+) from (\S+)')
sftp_pattern = re.compile(r'(^\S+).*Starting session: subsystem \'sftp\' for user (\S+)')
root_session_pattern = re.compile(r'(^\S+).*session opened for user root')

events = []
fn = print(input("Enter the filename :"))
print("Analyzing log file for security events...")

with open(fn, 'r') as log_file:
    for line in log_file:
        success_match = success_pattern.search(line)
        sftp_match = sftp_pattern.search(line)
        root_match = root_session_pattern.search(line)

        if success_match:
            timestamp, user, ip_address = success_match.groups()
            events.append(f"[{timestamp}] SUCCESSFUL LOGIN: User '{user}' logged in from IP {ip_address}")
        elif sftp_match:
            timestamp, user = sftp_match.groups()
            events.append(f"[{timestamp}] SFTP SESSION: User '{user}' started an SFTP file transfer session.")
        elif root_match:
            timestamp = root_match.group(1)
            events.append(f"[{timestamp}] ROOT ACTIVITY: A session was opened for the root user (check for cron jobs or direct login).")

if events:
    for event in events:
        print(event)
else:
    print("No notable security events found.")