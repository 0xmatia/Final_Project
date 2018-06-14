from scapy.layers.inet import *
from scapy.layers.inet6 import IPv6
from scapy.sendrecv import *
import requests
import socket

SERVER_PORT = 8200
BOSS_IP = "127.0.0.1"
NUM_OF_PACKETS = 250
IP_API = "http://ip-api.com/json/"
MACHINE_IP = ""

ip_locations = {}
packet_list = []  # the list is being erased every NUM_OF_PACKETS times


# https://stackoverflow.com/questions/159137/getting-mac-address


def main():
    global MACHINE_IP
    MACHINE_IP = get_ip()  # assign the machine ip
    while True:  # the function runs forever
        packet_list.clear()
        sniff(lfilter=sniff_filter, prn=process_packet, count=NUM_OF_PACKETS)
        get_ip_location()
        assign_location()
        print(packet_list)
        quit()


def sniff_filter(packet):
    """
    the function checks if the packet given is udp or tcp and above ip layer (only Ipv4 otherwise the program crashes)
    in addition, it makes sure that the packet is from or to this machine (not in promisc mouse)
    :param packet: the packet to check
    :return: true if the packet is valid, false otherwise
    :rtype: bool
    """
    return ((IP in packet) and not (IPv6 in packet and packet[IPv6].version == 6)) and (
                (packet[IP].src == MACHINE_IP) or (packet[IP].dst == MACHINE_IP)) and (TCP in packet) or (UDP in packet)


def process_packet(packet):
    """
    The function receive a packet and analyzes it and puts it in a dictionary, then appends it to the global packet list
    :param packet: the packet to analyze
    :type packet: packet
    :return: None
    """
    #  find packet type:

    temp_dict = {}
    if TCP in packet:
        p_type = packet[TCP]
    else:
        p_type = packet[UDP]
    # find the IP of the server
    if packet[IP].src == MACHINE_IP:
        packet_dst = packet[IP].dst
        temp_dict["outgoing"] = True
    else:
        packet_dst = packet[IP].src
        temp_dict["outgoing"] = False
    print(str(packet[IP].src) + ":" + str(p_type.sport) + " ==> " + str(packet[IP].dst) + ":" + str(p_type.dport))

    temp_dict["ip"] = packet_dst

    temp_dict["dport"] = p_type.dport
    temp_dict["size"] = len(packet)
    packet_list.append(temp_dict)  # add the packet information to the global packet list


def init():
    """
    The function prints some basic information to the user
    :return: None
    """
    print("Welcome to BossSniffer agent! Let's verify some information before we begin.")
    print("The IP of the boss: " + BOSS_IP)
    print("The port: " + str(SERVER_PORT))
    print("The number of packets per cycle: " + str(NUM_OF_PACKETS))
    print("You can modify these values in the constants area. Continue? y/n")
    choice = input()
    if choice == "n":
        quit()
    print("\nStarting now.\n")


def get_ip_location():
    """
    The function finds locations of given IP. if the lookup fails (mostly because of private ips in the same subnet)
    :return: None
    """
    for packet in packet_list:
        if packet["ip"] in ip_locations.keys():  # if the ip is in the dictionary, we know its location
            packet["country"] = ip_locations[packet["ip"]]
        else:
            response = requests.get(IP_API + packet["ip"])
            html = response.json()
            if "fail" not in html.values():  # if the operation succeeded
                ip_locations[packet["ip"]] = html["country"]
            else:  # the location lookup failed.
                ip_locations[packet["ip"]] = "unknown location"

    print(ip_locations)


def assign_location():
    for packet in packet_list:
        packet["country"] = ip_locations[packet["ip"]]


def get_ip():
    """
    The function returns the ip of the machine. supports both windows and linux
    :return: the ip of the machine
    :rtype: str
    """

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(('8.8.8.8', 0))
    address = s.getsockname()[0]
    s.close()
    return address


if __name__ == '__main__':
    main()
