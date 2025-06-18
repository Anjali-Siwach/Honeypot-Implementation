import datetime
import json
import os

LOG_DIR = "honeypot_logs"
ANALYSIS_DIR = "honey-pot/analysis_reports"
os.makedirs(ANALYSIS_DIR, exist_ok=True)  # Ensure analysis folder exists

def analyze_logs(log_file):
    """Enhanced honeypot log analysis with temporal and behavioral patterns"""
    ip_analysis = {}
    port_analysis = {}
    hourly_attacks = {}
    data_patterns = {}

    # Track session patterns
    ip_sessions = {}
    attack_timeline = []

    # Create analysis file
    analysis_file = os.path.join(ANALYSIS_DIR, f"honeypot_analysis_{datetime.datetime.now().strftime('%Y%m%d')}.txt")

    with open(log_file, 'r') as f:
        for line in f:
            try:
                activity = json.loads(line)
                timestamp = datetime.datetime.fromisoformat(activity['timestamp'])
                ip = activity['remote_ip']
                port = activity['port']
                data = activity['data']

                # Initialize IP tracking if new
                if ip not in ip_analysis:
                    ip_analysis[ip] = {
                        'total_attempts': 0,
                        'first_seen': timestamp,
                        'last_seen': timestamp,
                        'targeted_ports': set(),
                        'unique_payloads': set(),
                        'session_count': 0
                    }

                # Update IP statistics
                ip_analysis[ip]['total_attempts'] += 1
                ip_analysis[ip]['last_seen'] = timestamp
                ip_analysis[ip]['targeted_ports'].add(port)
                ip_analysis[ip]['unique_payloads'].add(data.strip())

                # Track hourly patterns
                hour = timestamp.hour
                hourly_attacks[hour] = hourly_attacks.get(hour, 0) + 1

                # Analyze port targeting patterns
                if port not in port_analysis:
                    port_analysis[port] = {
                        'total_attempts': 0,
                        'unique_ips': set(),
                        'unique_payloads': set()
                    }
                port_analysis[port]['total_attempts'] += 1
                port_analysis[port]['unique_ips'].add(ip)
                port_analysis[port]['unique_payloads'].add(data.strip())

                # Track payload patterns
                if data.strip():
                    data_patterns[data.strip()] = data_patterns.get(data.strip(), 0) + 1

                # Track attack timeline
                attack_timeline.append({
                    'timestamp': timestamp,
                    'ip': ip,
                    'port': port
                })

            except (json.JSONDecodeError, KeyError) as e:
                continue

    # Generate analysis report
    with open(analysis_file, 'w') as report:
        report.write("\n=== Honeypot Analysis Report ===\n")

        # 1. IP-based Analysis
        report.write("\nTop 10 Most Active IPs:\n")
        sorted_ips = sorted(ip_analysis.items(), key=lambda x: x[1]['total_attempts'], reverse=True)[:10]
        for ip, stats in sorted_ips:
            duration = stats['last_seen'] - stats['first_seen']
            report.write(f"\nIP: {ip}\n")
            report.write(f"Total Attempts: {stats['total_attempts']}\n")
            report.write(f"Active Duration: {duration}\n")
            report.write(f"Unique Ports Targeted: {len(stats['targeted_ports'])}\n")
            report.write(f"Unique Payloads: {len(stats['unique_payloads'])}\n")

        # 2. Port Analysis
        report.write("\nPort Targeting Analysis:\n")
        sorted_ports = sorted(port_analysis.items(), key=lambda x: x[1]['total_attempts'], reverse=True)
        for port, stats in sorted_ports:
            report.write(f"\nPort {port}:\n")
            report.write(f"Total Attempts: {stats['total_attempts']}\n")
            report.write(f"Unique Attackers: {len(stats['unique_ips'])}\n")
            report.write(f"Unique Payloads: {len(stats['unique_payloads'])}\n")

        # 3. Temporal Analysis
        report.write("\nHourly Attack Distribution:\n")
        for hour in sorted(hourly_attacks.keys()):
            report.write(f"Hour {hour:02d}: {hourly_attacks[hour]} attempts\n")

        # 4. Attack Sophistication Analysis
        report.write("\nAttacker Sophistication Analysis:\n")
        for ip, stats in sorted_ips:
            sophistication_score = (
                len(stats['targeted_ports']) * 0.4 +  # Port diversity
                len(stats['unique_payloads']) * 0.6   # Payload diversity
            )
            report.write(f"IP {ip}: Sophistication Score {sophistication_score:.2f}\n")

        # 5. Common Payload Patterns
        report.write("\nTop 10 Most Common Payloads:\n")
        sorted_payloads = sorted(data_patterns.items(), key=lambda x: x[1], reverse=True)[:10]
        for payload, count in sorted_payloads:
            if len(payload) > 50:  # Truncate long payloads
                payload = payload[:50] + "..."
            report.write(f"Count {count}: {payload}\n")

    print(f"\n✅ Analysis saved to: {analysis_file}")

if __name__ == "__main__":
    log_files = [f for f in os.listdir(LOG_DIR) if f.endswith(".json")]
    if log_files:
        latest_log = os.path.join(LOG_DIR, sorted(log_files)[-1])
        analyze_logs(latest_log)
    else:
        print("❌ No log files found in honeypot_logs/")
