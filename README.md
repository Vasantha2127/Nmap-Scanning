# Nmap-Scanning
Step 1: Find Local IP Address
First, I identified the local IP address of the target machine on my network.

Step 2: Perform Nmap Scan
Next, I performed a network scan using Nmap to discover open ports and services running on the target IP.

Step 3: Analyze Scan Results
The scan revealed several open ports with different services:

Port 8008 is likely a web interface for Chromecast devices.
Port 8009 is used for secure Chromecast communication.
Port 8443 usually hosts a secure web interface.
Port 9000 may be a listener for remote commands or control.
Port 53 runs a DNS service called dnsmasq for domain name resolution.

Step 4: Identify Potential Security Risks
Each open port can pose risks if not properly secured:

Ports for Chromecast devices could allow unauthorized access.
Secure communication ports might be vulnerable to interception.
Web interfaces can be attacked if authentication or updates are weak.
Listener ports might be exploited for remote code execution.
DNS services can be targeted for spoofing or denial of service attacks.

Step 5: Summary
This task helped me understand how to find network information, scan for open services, and recognize possible security weaknesses that attackers might exploit.
