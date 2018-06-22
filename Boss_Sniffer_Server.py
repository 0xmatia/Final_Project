import socket
import json

LISTEN_PORT = 8200
FILE_PATH = "settings.dat"
LOG_TEMPLATE_PATH = "Logs/template.html"
DATA = ""
IP_SIZE_DICT = {}
COUNTRY_SIZE_DICT = {}


def main():
    global DATA
    path = input("Please enter path for the settings file. Press enter to user default: ")
    if path == "":
        path = FILE_PATH
    try:
        with open(path, "r") as file:  # read the settings file
            DATA = file.readline().split("\n")  # split workers from black list
    except Exception:
        print("Couldn't open file. Using defaults")
        with open(FILE_PATH, "r") as file:  # read the settings file
            DATA = file.readline().split("\n")  # split workers from black list
    # TODO: ADD THE OPTION TO CHOOSE THE LOG PATH
    connection = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    connection.bind(('', LISTEN_PORT))
    print("Boss server is up.")
    while True:
        client_msg, client_addr = connection.recvfrom(100000)
        user = who_is_it(client_addr)
        if user != "-1":
            print("Received report from {0}:\t".format(user), end="")
            print(json.loads(client_msg.decode()))
            update_log(json.loads(client_msg.decode()))
        else:
            print("Received report from unknown user. Stats won't be added to the log:\t", end="")
            print(json.loads(client_msg.decode()))
        print("\n")


def who_is_it(address):
    """
    The function checks in its database who sent the report
    :param address: The address of the report sender
    :type address: tuple
    :return: The name of the user (there is an ip - name), -1 otherwise.
    :rtype: str
    """
    workers = DATA[0][10:]
    ip = address[0]
    a = workers.split(",")  # split workers
    for i in range(0, len(a)):
        a[i] = tuple(a[i].split(":"))  # put each name and ip in a tuple as one element of a list
    for worker in a:
        if ip == worker[1]:
            return worker[0]
    return "-1"


def update_log(response):
    """
    Updates the graphs in the log.
    :param response: the response from the agent
    :type response: list
    :return: None
    """
    # traffic per ip
    update_traffic_per_ip(response)
    # traffic per country
    update_traffic_per_country(response)


def update_traffic_per_ip(response):
    """
   The function updates the html log every response
   :param response: the response from the agent
   :type response: list
   :return: none
   """
    ip_list = []
    size_list = []
    for item in response:
        if item["ip"] not in IP_SIZE_DICT.keys():
            IP_SIZE_DICT[item["ip"]] = int(item["size"])  # if the ip doesnt exist in the dictionary add it
        else:
            IP_SIZE_DICT[item["ip"]] += int(item["size"])  # otherwise add the size to existing key in the dictionary

    for key, value in IP_SIZE_DICT.items():
        ip_list.append(key)
        size_list.append(value)

    log = open(LOG_TEMPLATE_PATH, "r")
    temp = log.readlines()
    log.close()

    log = open(LOG_TEMPLATE_PATH, "w")
    temp[272] = "labels: " + str(ip_list) + ","  # update labels
    temp[276] = "data: " + str(size_list) + ""  # update update daa
    log.writelines(temp)  # write the updated information
    log.close()


def update_traffic_per_country(response):
    """
    The function updates the traffic per country graph
    :param response:  the response from the agent
    :type response: list
    :return: None
    """
    country_list = []
    size_list = []
    for item in response:
        if item["country"] not in COUNTRY_SIZE_DICT.keys():
            COUNTRY_SIZE_DICT[item["country"]] = int(
                item["size"])  # if the country doesnt exist in the dictionary add it
        else:
            COUNTRY_SIZE_DICT[item["country"]] += int(
                item["size"])  # otherwise add the size to existing key in the dictionary

    for key, value in COUNTRY_SIZE_DICT.items():
        country_list.append(key)
        size_list.append(value)

    log = open(LOG_TEMPLATE_PATH, "r")  # read the contents of the log.
    temp = log.readlines()
    log.close()

    log = open(LOG_TEMPLATE_PATH, "w")
    temp[225] = "labels: " + str(country_list) + ","  # update labels
    temp[229] = "data: " + str(size_list) + ""  # update update daa
    log.writelines(temp)  # write the updated information
    log.close()


if __name__ == '__main__':
    main()
