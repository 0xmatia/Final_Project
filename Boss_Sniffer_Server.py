import socket
import json

LISTEN_PORT = 8200
FILE_PATH = "settings.dat"

with open(FILE_PATH, "r") as file:  # read the settings file
    data = file.readline().split("\n")  # split workers from black list
    os

def main():
    print("Boss server is up. Opening socket")
    connection = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    connection.bind(('', LISTEN_PORT))
    while True:
        client_msg, client_addr = connection.recvfrom(100000)
        user = who_is_it(client_addr)
        if user != "-1":
            print("Received report from {0}:\t".format(user), end="")
        else:
            print("Received report from unknown user:\t", end="")
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
    workers = data[0][10:]
    ip = address[0]
    a = workers.split(",")  # split workers
    for i in range(0, len(a)):
        a[i] = tuple(a[i].split(":"))  # put each name and ip in a tuple as one element of a list
    for worker in a:
        if ip == worker[1]:
            return worker[0]
    return "-1"


if __name__ == '__main__':
    main()
