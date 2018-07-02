import socket
import json
import datetime
from shutil import copy

LISTEN_PORT = 8200
FILE_PATH = "settings.dat"
LOG_TEMPLATE_PATH = "Logs\\template.html"
DATA = ""
SERVER_IP = "54.71.128.194"
SERVER_PORT = 8808

blacklist = []
log_path = "Logs\\log.html"
blacklist_users = []
ip_size_dict = {}
country_size_dict = {}
program_size_dict = {}
port_size_dict = {}
incoming_user_size_dict = {}
outgoing_user_size_dict = {}
name = "elad.matia"


def main():
    global DATA
    global log_path
    global name
    path = input("Please enter path for the settings file. Press enter to use default: ")
    if path == "":
        path = FILE_PATH
    try:
        with open(path, "r") as file:  # read the settings file
            DATA = file.read().split("\n")
    except Exception:
        print("Couldn't open file. Using defaults")
        with open(FILE_PATH, "r") as file:  # read the settings file
            DATA = file.read().split("\n")
    blacklister()  # figure out what the black list ips are

    # ask for log name
    log_name = input(
        "Enter log file name with .html extension. all logs are saved in: Final_Project\Logs. Example: log1.html: ")
    while not log_name.endswith(".html"):
        log_name = input("Please enter a valid log name (like: log1.html): ")
    log_path = "Logs\\" + log_name
    while True:
        try:  # checking for valid file name
            copy(LOG_TEMPLATE_PATH, log_path)
        except Exception:
            choice = input("The program encountered a problem while trying to create a log. Please try again: ")
            log_path = "Logs\\" + choice
        else:  # the file path is valid! we can exit the loop
            break

    name = input("Enter your name in the following format: {firstname.lastname}:  ")
    while '.' not in name:
        name = input("Try again. name format: {firstname.lastname}")
    s_name = name.split(".")
    print("Log is saved locally in: {" + log_path + "} and remotely in: http://" + s_name[0] + "_" + s_name[1] + ".bossniffer.com")
    connection = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    connection.bind(('', LISTEN_PORT))
    print("Boss server is up.")
    while True:
        client_msg, client_addr = connection.recvfrom(100000)
        user = who_is_it(client_addr)
        if user != "-1":
            print("Received report from {0} --> ".format(user), end="")
            update_log(json.loads(client_msg.decode()), user)
            try:
                upload_log()  # upload the log to the server
            except Exception:
                print("We encountered a problem while trying to upload the log. Skipping.")
        else:
            print("Received report from unknown user. Stats won't be added to the log.\t", end="")
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
    # update time:

    now = datetime.datetime.now()
    time_sig = str(now.day) + "." + str(now.month) + "." + str(now.year) + ", " + str(now.hour) + ":" + str(now.minute)
    with open(log_path, "r+") as log:
        temp = log.readlines()
        log.seek(0)
        log.truncate()
        temp[114] = "<p>Last update: " + time_sig + "</p>\n"
        log.writelines(temp)

    # update traffic per ip
    update_traffic(response, 272, 276, ip_size_dict, "ip")
    # update traffic per country
    update_traffic(response, 225, 229, country_size_dict, "country")
    # update traffic per program
    update_traffic(response, 317, 321, program_size_dict, "prog")
    # update traffic per port
    update_traffic(response, 364, 368, port_size_dict, "dport")
    # update agent specific stats
    agent_traffic_incoming(response, user)
    agent_traffic_outgoing(response, user)
    # update alerts
    update_alerts(response, user)


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
   :param element: which part of the protocol we want to extract (prog / port/ ip etc)
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

    with open(log_path, "r+") as log:
        temp = log.readlines()
        log.seek(0)
        log.truncate()

        temp[num1] = "                       labels: " + str(x_axis) + ",\n"  # update labels
        temp[num2] = "                       data: " + str(size_list) + "\n"  # update update daa
        log.writelines(temp)  # write the updated information


def agent_traffic_outgoing(response, user):
    """
    The function updates the outgoing graph stats
    :param response: the response from the client
    :type response: list
    :param user: the user who sent the response (being extracted from the settings.dat file, uses the who_is_it function)
    :type user: str
    :return: None
    """
    # response came from user
    global outgoing_user_size_dict

    size_list = []
    x_axis = []
    num1 = 0
    num2 = 0
    for item in response:
        if item["outgoing"]:
            num1 = 180
            num2 = 184
            if user not in outgoing_user_size_dict.keys():  # create a dictionary of names and size
                outgoing_user_size_dict[user] = int(item["size"])
            else:
                outgoing_user_size_dict[user] += int(item["size"])

    for key, value in outgoing_user_size_dict.items():  # separate the listS
        x_axis.append(key)
        size_list.append(value)

    with open(log_path, "r+") as log:
        temp = log.readlines()
        log.seek(0)
        log.truncate()

        temp[num1] = "                       labels: " + str(x_axis) + ",\n"  # update labels
        temp[num2] = "                       data: " + str(size_list) + "\n"  # update update daa
        log.writelines(temp)  # write the updated information


def agent_traffic_incoming(response, user):
    """
    The function updates the incoming graph stats
    :param response: the response from the client
    :type response: list
    :param user: the user who sent the response (being extracted from the settings.dat file, uses the who_is_it function)
    :type user: str
    :return: None
    """
    # response came from user
    global incoming_user_size_dict

    size_list = []
    x_axis = []
    num1 = 0
    num2 = 0
    for item in response:
        if not item["outgoing"]:
            num1 = 152
            num2 = 156
            if user not in incoming_user_size_dict.keys():  # create a dictionary of names and size
                incoming_user_size_dict[user] = int(item["size"])
            else:
                incoming_user_size_dict[user] += int(item["size"])

    for key, value in incoming_user_size_dict.items():  # separate the listS
        x_axis.append(key)
        size_list.append(value)

    with open(log_path, "r+") as log:
        temp = log.readlines()
        log.seek(0)
        log.truncate()

        log = open(log_path, "w")  # update the log
        temp[num1] = "                       labels: " + str(x_axis) + ",\n"  # update labels
        temp[num2] = "                       data: " + str(size_list) + "\n"  # update update daa
        log.writelines(temp)  # write the updated information


def blacklister():
    """
    The function updates the black list ips
    :return: None
    """
    global blacklist
    a = DATA[1][12:].split(",")
    for i in a:
        blacklist.append(i[:i.find(":")])


def update_alerts(response, user):
    """
    The function updates the alerts section in the report
    :param response: the response from the user
    :type response: list
    :param user: the user who send the response
    :type user: str
    :return: None
    """
    global blacklist
    for item in response:
        if item["ip"] in blacklist:
            blacklist_users.append((user, item["ip"]))
            blacklist.remove(item[
                                 "ip"])  # because someone has already entered the ip, we can remove it from the blacklist so it won't be added again and again
    with open(log_path, "r+") as log:
        temp = log.readlines()
        log.seek(0)
        log.truncate()

        log = open(log_path, "w")
        temp[403] = str(blacklist_users)
        log.writelines(temp)


def upload_log():
    """
    The function uploads the log to the boss sniffer server.
    :return: None
    """
    with open(log_path, "r") as file:
        html = file.read()
        file_size = len(html)  # the size of the log
    connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # open a socket

    connection.connect((SERVER_IP, SERVER_PORT))  # connect to the server
    connection.sendall(("400#USER="+name).encode())  # first, send the name to the server
    connection.recv(1024)

    connection.sendall(("700#SIZE="+str(file_size)+",HTML="+html).encode())
    answer = connection.recv(1024).decode()

    if "705" in answer:
        print("Log uploaded successfully!")
    else:
        print("Something went wrong while trying to upload the log. Moving on")
        print(answer)
    connection.close()


if __name__ == '__main__':
    main()
