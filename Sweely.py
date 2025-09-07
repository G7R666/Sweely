import argparse
import pyttsx3
from scapy.all import sniff, IP, TCP, UDP
import threading

# Initialize text-to-speech engine once
engine = pyttsx3.init()
engine.setProperty('rate', 150)

# Lock to avoid multiple threads speaking at the same time
lock = threading.Lock()

def play_alert():
    with lock:
        engine.say("This is not a test, this is an emergency in the system")
        engine.runAndWait()

def packet_callback(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = "OTHER"

        if TCP in packet:
            protocol = "TCP"
        elif UDP in packet:
            protocol = "UDP"

        print(f"[!!!] Potential attack detected from {src_ip}")
        print(f"[{protocol}] {src_ip} -> {dst_ip} | Port: {packet[IP].sport if TCP in packet or UDP in packet else 'N/A'}")

        # Trigger alert sound in a separate thread
        threading.Thread(target=play_alert).start()

def main():
    parser = argparse.ArgumentParser(description="Network Intrusion Detection Tool")
    parser.add_argument("-i", "--interface", required=True, help="Network interface to sniff on")
    args = parser.parse_args()

    print(f"[*] Starting network monitoring on {args.interface}...")
    sniff(iface=args.interface, prn=packet_callback, store=False)

if __name__ == "__main__":
    main()
