import os

program_dict = {}


def main():
    netstat()


def netstat():
    netstat_command = os.popen("netstat -nb", "r", 1).read().split("\n")[4:]  # without the headlines
    for i in range(len(netstat_command)):
        if "[" in netstat_command[i]:  # one time in my computer i saw connections from 127.0.0.1 to 127.0.0.1 with no name so I checked
            prog = netstat_command[i][2:-1]
            ip = netstat_command[i - 1]
            dest_ip = ""
            check_from = ip.find(":") + 6
            for c in range(check_from, len(ip)):
                if ip[c] == ":":  # if we reached the port
                    break
                if ip[c].isnumeric() or ip[c] == ".":
                    dest_ip += ip[c]
            program_dict[dest_ip] = prog
    print(program_dict)
    print(len(program_dict))

if __name__ == '__main__':
    main()
