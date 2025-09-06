#!/usr/bin/env python3
# Sweely - Advanced Network Traffic Monitor with Logging
# Developed by: Security Analyst

import scapy.all as scapy
import threading
import time
import pyttsx3

# إعداد محرك الصوت للتنبيه
engine = pyttsx3.init()
engine.setProperty("rate", 150)  # سرعة الكلام
engine.setProperty("volume", 1.0)  # مستوى الصوت

# رسالة الطوارئ
ALERT_MESSAGE = "This is not a test. This is an emergency in the system."

# ملف تسجيل
LOG_FILE = "sweely_log.txt"

# قائمة لتخزين الاتصالات المشبوهة
suspicious_ips = {}

# حدود التهديد
THRESHOLD = 50


def log_event(message):
    """تسجيل الأحداث في ملف نصي"""
    with open(LOG_FILE, "a") as f:
        f.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {message}\n")


def play_alert():
    """تشغيل تنبيه صوتي"""
    engine.say(ALERT_MESSAGE)
    engine.runAndWait()


def analyze_packet(packet):
    """تحليل الحزم الملتقطة"""
    if packet.haslayer(scapy.IP):
        src_ip = packet[scapy.IP].src
        dst_ip = packet[scapy.IP].dst

        suspicious_ips[src_ip] = suspicious_ips.get(src_ip, 0) + 1

        if suspicious_ips[src_ip] > THRESHOLD:
            alert_msg = f"[!!!] Potential attack detected from {src_ip} ({suspicious_ips[src_ip]} packets)"
            print(alert_msg)
            log_event(alert_msg)
            threading.Thread(target=play_alert, daemon=True).start()

        if packet.haslayer(scapy.TCP):
            msg = f"[TCP] {src_ip} -> {dst_ip} | Port: {packet[scapy.TCP].dport}"
            print(msg)
            log_event(msg)
        elif packet.haslayer(scapy.UDP):
            msg = f"[UDP] {src_ip} -> {dst_ip} | Port: {packet[scapy.UDP].dport}"
            print(msg)
            log_event(msg)


def reset_counter():
    """إعادة تعيين العدّ كل دقيقة"""
    global suspicious_ips
    while True:
        time.sleep(60)
        suspicious_ips = {}


def detect_interface():
    """اختيار واجهة الشبكة تلقائياً"""
    interfaces = scapy.get_if_list()
    if not interfaces:
        raise Exception("No network interfaces found!")

    print("\n[*] Available interfaces:")
    for i, iface in enumerate(interfaces):
        print(f"  {i + 1}. {iface}")

    choice = input("\nSelect interface (default=1): ")
    try:
        idx = int(choice) - 1
        return interfaces[idx]
    except:
        return interfaces[0]


def main():
    print("""
     ███████╗██╗    ██╗███████╗███████╗██╗  ██╗   ██╗
     ██╔════╝██║    ██║██╔════╝██╔════╝██║  ╚██╗ ██╔╝
     ███████╗██║ █╗ ██║█████╗  █████╗  ██║   ╚████╔╝ 
     ╚════██║██║███╗██║██╔══╝  ██╔══╝  ██║    ╚██╔╝  
     ███████║╚███╔███╔╝███████╗██║     ███████╗██║   
     ╚══════╝ ╚══╝╚══╝ ╚══════╝╚═╝     ╚══════╝╚═╝   

     Sweely - Real-Time Network Threat Monitor
     Version 4.0 | By Security Researcher
    """)

    # تشغيل عداد التصفير
    threading.Thread(target=reset_counter, daemon=True).start()

    # كشف الواجهة
    iface = detect_interface()
    print(f"\n[*] Monitoring network traffic on interface: {iface}\n")
    log_event(f"Started monitoring on {iface}")

    scapy.sniff(iface=iface, store=False, prn=analyze_packet)


if __name__ == "__main__":
    main()
