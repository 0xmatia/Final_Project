from scapy.layers.inet import *
from scapy.sendrecv import *
from uuid import getnode as get_mac
import requests
import socket

SERVER_PORT = 8200
BOSS_IP = "127.0.0.1"
NUM_OF_PACKETS = 250
IP_API = "http://ip-api.com/json/"

ip_locations = {}
packet_list = []  # the list is being erased every NUM_OF_PACKETS times
my_mac = ':'.join(("%012X" % get_mac())[i:i + 2] for i in range(0, 12, 2))  # getting the mac of the interface:


# https://stackoverflow.com/questions/159137/getting-mac-address


def main():

    print(my_mac)
    while True:  # the function runs forever
        packet_list.clear()
        sniff(lfilter=sniff_filter, prn=process_packet, count=NUM_OF_PACKETS)
        get_ip_location()


def sniff_filter(packet):
    """
    the function checks if the packet given is udp or tcp and above ip layer (only Ipv4 otherwise the program crashes)
    :param packet: the packet to check
    :return: true if the packet is valid, false otherwise
    :rtype: bool
    """
    return (IP in packet) and (TCP in packet) or ((UDP in packet) and ((packet[ UDP].sport != 5353) or  # mDNS protocol use ipv6 and crashes the program. the only solution i could find
                                                                       (packet[UDP].dport != 5353)))


def process_packet(packet):
    """
    The function receive a packet and analyzes it and puts it in a dictionary, then appends it to the global packet list
    :param packet: the packet to analyze
    :type packet: packet
    :return: None
    """
    #  find packet type:
    if TCP in packet:
        p_type = packet[TCP]
    else:
        p_type = packet[UDP]
    print(str(packet[IP].src) + ":" + str(p_type.sport) + " ==> " + str(packet[IP].dst) + ":" + str(p_type.dport))
    temp_dict = {"ip": packet[IP].src, "country": ""}
    if str(packet[Ether].src).upper() == str(my_mac):  # checking if the packet from my computer
        temp_dict["outgoing"] = True
    else:
        temp_dict["outgoing"] = False

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
    print("You can modify these values in the constants area. Continue?y/n")
    choice = input()
    if choice == "n":
        quit()
    print("\nStarting now.\n")


def get_ip_location():
    for packet in packet_list:
        if packet["ip"] in ip_locations.keys():  # if the ip is in the dictionary, we know its location
            packet["country"] = ip_locations[packet["ip"]]
        else:
            response = requests.get(IP_API+packet["ip"])
            html = response.json()
            print(html)
            if "fail" not in html.values():  # if the operation succeeded
                ip_locations[packet["ip"]] = html["country"]
    print(ip_locations)
    quit()


if __name__ == '__main__':
    main()
