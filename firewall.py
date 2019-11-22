from collections import defaultdict

def _ip_to_int(s):
    """ Given an input ip address, return its value in integer.
    
    Arguments:
    -----
    s (str): Input ip address whose type is str, E.g. 1.255.1.1

    Returns:
    -----
    int: The integer representation of ip address s, E.g. 33489153
    """
    val_list = s.split(".")
    if len(val_list) != 4:
        raise Exception("ip string {} is not valid, note that space is not allowed!".format(s))
    output_ip = 0
    for i, val in enumerate(reversed(val_list)):
        if val.isdigit() and 0 <= int(val) < 256:
            output_ip += 2**(8*i)*int(val)
        else:
            raise Exception("ip string {} is not valid, note that space is not allowed!".format(s))
    return output_ip


class FireWall(object):
    """A firewall that can decide whether to accept a packet based on the rules from the file

    Arguments:
    -----
    filename (str): 
        A csv file. Each line contains a rule 
        (direction, protocol, port, ip_address)
    
    Attributes:
    -----
    rules (defaultdict):
        A dict contains all the rules read from the file. 
        It maps a tuple (direction, protocol) to a list, which store all
        relevant port ranges and ip ranges of the tuple.
    """
    def __init__(self, filename):
        """Initialize the Firewall using the rules in file"""

        # Stores all rules in the dictionary that maps to a list. The list contains 
        # four integer, including start and end point of port and ip address
        self.rules = defaultdict(list)
        with open(filename, "r") as f:
            for line in f:
                direction, protocol, port, ip_address = line.strip().split(",")
                # Process input data to approiate format
                if "-" in port:
                    l_port, r_port = port.split("-")
                else:
                    l_port = r_port = port
                l_port = int(l_port)
                r_port = int(r_port)
                if "-" in ip_address:
                    l_ip, r_ip = ip_address.split("-")
                else:
                    l_ip = r_ip = ip_address
                # Transform ip addrees string to integer
                l_ip = _ip_to_int(l_ip)
                r_ip = _ip_to_int(r_ip)
                self.rules[(direction, protocol)].append((l_port, r_port, l_ip, r_ip))
        return
    
    def accept_packet(self, direction, protocol, port, ip_address):
        """Return True if the conditions specified by all the arguments 
        exists in the rules, false otherwise. Time complexity: O(n),
        where n is the number of rules (input data size)

        Arguments:
        -----
        direction (str): 
        protocol (str):
        port (int):
        ip_address (str)
        """
        if (direction, protocol) not in self.rules:
            return False
        cur_list = self.rules[(direction, protocol)]
        cur_ip = _ip_to_int(ip_address)
        # Check all values in the rules. If none is true, reture False.
        for l_port, r_port, l_ip, r_ip in cur_list:
            if l_port <= port <= r_port and l_ip <= cur_ip <= r_ip:
                return True
        return False
