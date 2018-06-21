import os

program_dict = {}


def main():
    print(netstat("204.79.197.213"))


def netstat(ip):
    netstat_command = os.popen("netstat -nb", "r", 1).read().split("\n")[4:]  # without the headlines
    print(netstat_command)
    for i in range(0, len(netstat_command)):
        if ip in netstat_command[i] and "TIME_WAIT" not in netstat_command[i]:
            return netstat_command[i+1][2:-1]
    return "-1"


if __name__ == '__main__':
    main()
