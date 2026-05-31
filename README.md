# DNS Spoofing & ARP Poisoning Laboratory Tool

A modular, Python-based network analysis tool designed to demonstrate localized Man-in-the-Middle (MitM) attacks inside an authorized testing environment. It combines concurrent thread-based ARP poisoning with OS-level `netfilterqueue` routing to cleanly intercept and selectively modify target DNS traffic without causing network-wide race conditions.

## ⚠️ Disclaimer
This software is developed strictly for educational purposes, security research, and authorized penetration testing within an isolated lab environment. Running this tool against networks or devices without explicit, written consent from the owner is illegal. The author assumes no liability for misuse or damage caused by this program.

---

## Features
* **Zero-Race Condition Interception**: Utilizes Linux `NFQUEUE` via `iptables` to halt and inspect packets in user-space before the kernel forwards them.
* **Selective Whitelisting**: Resolves and caches a list of safe domains locally; matching queries are cleanly passed through to the gateway, while undefined queries are redirected.
* **Automated Cleanup**: Catches termination signals (`CTRL+C`) to restore original ARP caches, flush active firewall rules, and reset the host kernel's `ip_forward` configuration.
* **Layer-Isolation Safety**: Prevents Scapy layer mutation defects by enforcing clean `DNSQR` structures per spoofed reply.

---

## Technical Prerequisites

### Operating System Requirements
* **Linux Kernel**: A Linux environment (e.g., Kali Linux, Ubuntu, Debian) supporting `/proc/sys/net/ipv4/ip_forward` and `iptables`.
* **Root Privileges**: Administrative (`sudo`) access is mandatory to alter network interfaces, write raw sockets, and modify kernel tables.

### System Dependencies
You must install the development headers for NetfilterQueue and `build-essential` tools to compile the Python bindings properly.

```bash
sudo apt-get update
sudo apt-get install build-essential python3-dev libnetfilter-queue-dev iptables
```

### Python Dependencies
Install the required network manipulation and queueing libraries:

```bash
pip3 install scapy NetfilterQueue
```

---

## Deployment & Usage

### 1. Lab Architecture Setup
Ensure your target device and your attacker machine are on the same local network subnet. Identify the local IP addresses for both your target host and your default gateway/router.

### 2. Network Layout Verification
Ensure your configuration matches your virtual lab variables:
* **Target IP**: `192.168.1.50` (Example host machine)
* **Gateway IP**: `192.168.1.1` (Example router)

### 3. Execution
Execute the script as `root`, passing the target and gateway IPs as command-line arguments:

```bash
sudo python3 main.py <TARGET_IP> <GATEWAY_IP>
```

*Example:*
```bash
sudo python3 main.py 192.168.1.50 192.168.1.1
```

### 4. Halting and Teardown
To cleanly exit the script, press **`CTRL + C`**. 
The program will automatically intercept the signal and perform the following teardown sequence:
1. Stop the asynchronous packet processor.
2. Terminate the background ARP poisoning daemon threads.
3. Broadcast legitimate ARP correction packets to both the target and the gateway to re-align network states.
4. Delete the added `FORWARD` rule from the `iptables` chain.
5. Revert `ip_forward` to its original operating system state.

---

## Structural Code Breakdown

* **`arp_loop()`**: Runs inside a dedicated background thread to periodically broadcast forged ARP replies, keeping the target's and gateway's cache tables poisoned.
* **`manage_iptables()`**: Appends an explicit forwarding rule (`-j NFQUEUE --queue-num 1`) directing outbound target DNS traffic (UDP port 53) to user space memory queue `1`.
* **`process_packet()`**: Reads the payload out of `NFQUEUE`. If the DNS query matches `WHITELIST_DOMAINS`, it triggers `.accept()` to pass it normally. Otherwise, it sends a forged DNS authoritative response (`DNSRR`) pointing to the local machine and drops (`.drop()`) the authentic request.
