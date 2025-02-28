import re

# List of suspicious patterns to look for
suspicious_patterns = [
    "failed login",
    "unauthorized access",
    "malicious activity detected"
]

def check_logs(file_path):
    try:
        # Open the log file
        with open(file_path, 'r') as file:
            # Read file line by line
            for line in file:
                # Check each pattern
                for pattern in suspicious_patterns:
                    # If pattern is found in the line
                    if re.search(pattern, line, re.IGNORECASE):
                        # Extract timestamp if present (assuming it's at the start of the line)
                        timestamp_match = re.match(r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}", line)
                        timestamp = timestamp_match.group() if timestamp_match else "Unknown time"
                        # Generate alert
                        print(f"ALERT: {pattern.upper()} DETECTED AT {timestamp}")
    except FileNotFoundError:
        print("Error: Log file not found.")
    except Exception as e:
        print(f"An error occurred: {e}")

# Example usage:
log_file_path = "system_logs.txt"
check_logs(log_file_path)
