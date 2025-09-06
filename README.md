Sweely - Real-Time Network Monitoring Tool

Sweely is a Python-based tool designed to monitor network traffic in real-time, detect suspicious activity, and alert the user immediately. It is ideal for security analysts, penetration testers, and network administrators who need a lightweight and efficient tool to track network behavior.

🎯 Purpose and Functions

Sweely’s main purpose is to provide real-time network monitoring with automated alerts for potential threats. Its core functions include:

Monitor Network Traffic

Tracks incoming and outgoing packets on a specified network interface (e.g., eth0).

Helps identify unusual patterns or unexpected traffic sources.

Detect Multiple IPs

Detects multiple IP addresses connecting to your network simultaneously.

Configurable limit to avoid false positives or misinterpretation as DDoS attacks.

Audio Alerts

Provides an immediate voice alert for suspicious activity:

"This is not a test. This is an emergency in the system."

Lightweight and Fast

Runs entirely in Python without heavy dependencies.

Suitable for continuous monitoring on Linux systems.



⚡ Features

Real-Time Monitoring: Continuous observation of network traffic on your chosen interface.

Suspicious Activity Detection: Flags unusual behavior, multiple IP connections, or abnormal traffic spikes.

Configurable Limits: Set thresholds for IP detection to reduce false alarms.

Audio Notifications: Instant voice alert for emergencies, enhancing awareness.

Easy Installation: Python-based, requires only minimal dependencies (pyttsx3, scapy).

Safe and Educational: Can be used for learning network security or testing networks you own or have permission to monitor.


install

pip install pyttsx3 scapy

git clone https://github.com/G7R666/Sweely.git

cd Sweely

pip install -r requirements.txt

python3 Sweely.py -i eth0

