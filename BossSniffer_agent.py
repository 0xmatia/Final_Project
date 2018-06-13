from scapy.layers.inet import *
from scapy.sendrecv import *
from uuid import getnode as get_mac
import socket

SERVER_PORT = 8200
BOSS_IP = "127.0.0.1"
NUM_OF_PACKETS = 250

packet_list = []  # the list is being erased every NUM_OF_PACKETS times
my_mac = ':'.join(("%012X" % get_mac())[i:i+2] for i in range(0, 12, 2))  # getting the mac of the interface:
# https://stackoverflow.com/questions/159137/getting-mac-address


def main():
    init()
    print(my_mac)
    while True:  # the function runs forever
        packet_list.clear()
        sniff(lfilter=sniff_filter, prn=process_packet, count=NUM_OF_PACKETS)


def sniff_filter(packet):
    """
    the function checks if the packet given is udp or tcp and above ip layer (only Ipv4 otherwise the program crashes)
    :param packet: the packet to check
    :return: true if the packet is valid, false otherwise
    :rtype: bool
    """
    return ((IP in packet) and (packet[IP].version == 4)) and (TCP in packet) or (UDP in packet)


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
    packet.show()
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
    print("You can modify these values in the constants area. \nStarting now.\n")


if __name__ == '__main__':
    main()
