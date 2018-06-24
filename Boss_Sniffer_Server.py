import socket
import json

LISTEN_PORT = 8200
FILE_PATH = "settings.dat"
LOG_TEMPLATE_PATH = "Logs/template.html"
DATA = ""

ip_size_dict = {}
country_size_dict = {}
program_size_dict = {}
port_size_dict = {}
incoming_user_size_dict = {}
outgoing_user_size_dict = {}


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
            update_log(json.loads(client_msg.decode()), user)
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


def update_log(response, user):
    """
    Updates the graphs in the log.
    :param response: the response from the agent
    :type response: list
    :param user: the sender of this packet
    :type user: str
    :return: None
    """
    global ip_size_dict
    global country_size_dict
    global program_size_dict
    global port_size_dict
    # TODO: update time
    # update traffic per ip
    update_traffic(response, 272, 276, ip_size_dict, "ip")
    # update traffic per country
    update_traffic(response, 225, 229, country_size_dict, "country")
    # update traffic per program
    update_traffic(response, 317, 321, program_size_dict, "prog")
    # update traffic per port
    update_traffic(response, 364, 368, port_size_dict, "dport")
    # update agent specific stats
    agent_traffic(response, user)


def update_traffic(response, num1, num2, dictionary, element):
    """
   The function updates a given graph with the latest response from the agent
   :param response: the response from the agent
   :type response: list
   :param num1: the line number of the label data set -1
   :type num1: int
   :param num2: the line number of the actual data set -1
   :type num2: int
   :param dictionary: the dictionary with size and prog \ port \ ip etc
   :type dictionary: dict
   :param element: what part of the protocol we want to extract (prog / port/ ip etc)
   :return: none
   """
    x_axis = []
    size_list = []
    for item in response:
        if item[element] not in dictionary.keys():
            dictionary[item[element]] = int(item["size"])  # if the ip doesnt exist in the dictionary add it
        else:
            dictionary[item[element]] += int(item["size"])  # otherwise add the size to existing key in the dictionary

    for key, value in dictionary.items():
        x_axis.append(key)
        size_list.append(value)

    log = open(LOG_TEMPLATE_PATH, "r")
    temp = log.readlines()
    log.close()

    log = open(LOG_TEMPLATE_PATH, "w")
    temp[num1] = "                       labels: " + str(x_axis) + ",\n"  # update labels
    temp[num2] = "                       data: " + str(size_list) + "\n"  # update update daa
    log.writelines(temp)  # write the updated information
    log.close()


def agent_traffic(response, user):
    # response came from user
    global outgoing_user_size_dict
    global incoming_user_size_dict

    size_list = []
    x_axis = []
    num1 = 0
    num2 = 0
    for item in response:
        if item["outgoing"]:
            num1 = 152
            num2 = 156
            if user not in outgoing_user_size_dict.keys():  # create a dictionary of names and size
                outgoing_user_size_dict[user] = int(item["size"])
            else:
                outgoing_user_size_dict[user] += int(item["size"])
            for key, value in outgoing_user_size_dict.items():  # separate the list
                x_axis.append(key)
                size_list.append(value)

        else:
            num1 = 180
            num2 = 184
            if user not in incoming_user_size_dict.keys():
                incoming_user_size_dict[user] = int(item["size"])
            else:
                incoming_user_size_dict[user] += int(item["size"])
            for key, value in outgoing_user_size_dict.items():
                x_axis.append(key)
                size_list.append(value)

    log = open(LOG_TEMPLATE_PATH, "r")
    temp = log.readlines()
    log.close()

    log = open(LOG_TEMPLATE_PATH, "w")  # update the log
    temp[num1] = "                       labels: " + str(x_axis) + ",\n"  # update labels
    temp[num2] = "                       data: " + str(size_list) + "\n"  # update update daa
    log.writelines(temp)  # write the updated information
    log.close()


if __name__ == '__main__':
    main()
