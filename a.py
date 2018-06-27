import socket
import os
import shutil

SERVER_IP = "54.71.128.194"
SERVER_PORT = 8808


log_path = "Logs\\log.html"


def main():
    shutil.copy("Logs\\template.html", "Logs\\log.html")

    with open(log_path, "r+") as log:
        temp = log.readlines()
        log.seek(0)
        log.truncate()
        temp[114] = "<p>Last update: " + "I wanna kill myself" + "</p>\n"
        log.writelines(temp)
    upload_log()  # upload the log to the server


def upload_log():
    """
    The function uploads the log to the boss sniffer server.
    :return: None
    """
    print(log_path)
    with open(log_path, "r") as file:
        html = file.read()
        file_size = len(html)  # the size of the log
    connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # open a socket and connect to the server

    connection.connect((SERVER_IP, SERVER_PORT))
    connection.sendall(("400#USER=" + "elad.matia").encode())  # first, send the name to the server
    connection.recv(1024)

    connection.sendall(("700#SIZE=" + str(file_size) + ",HTML=" + html).encode())
    print("a")
    answer = connection.recv(1024).decode()
    if "705" in answer:
        print("Log uploaded successfully!")
    else:
        print("Something went wrong while trying to upload the log. Moving on")
    connection.close()


if __name__ == '__main__':
    main()