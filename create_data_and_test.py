import random
import time
import firewall

def _int_to_ip(val):
    """ Given an input ip as an integer, return its string representation.
    
    Arguments:
    -----
    val (int): Input ip address whose type is int, E.g. 33489153

    Returns:
    -----
    str: The string representation of the ip address val, E.g. 1.255.1.1
    """
    cur_s = []
    for i in range(3, -1, -1):
        base = 2**(8*i)
        cur_s.append(str(val//base))
        val %= base
    return ".".join(cur_s)

def generate_data(output_file, n_line):
    """Randomly Generate data of size n_line to output_file"""

    directions = ["inbound", "outbound"]
    protocols = ["tcp", "udp"]
    # Generate Data
    with open("fw2.csv", "w") as f:
        for _ in range(n_line):
            cur_direction = str(random.choice(directions))
            cur_protocol = str(random.choice(protocols))
            if random.random() > 0.5:
                l_port = random.randint(1, 65535)
                r_port = random.randint(l_port, 65535)
                cur_port = "-".join([str(l_port), str(r_port)])
            else:
                cur_port = str(random.randint(1, 65535))
            if random.random() > 0.5:
                l_ip = random.randint(0, 2**32-1)
                r_ip = random.randint(l_ip, 2**32-1)
                l_ip = _int_to_ip(l_ip)
                r_ip = _int_to_ip(r_ip)
                cur_ip = "-".join([l_ip, r_ip])
            else:
                cur_ip = ".".join(str(random.randint(0, 255)) for j in range(4))
            cur_s = ",".join([cur_direction, cur_protocol, cur_port, cur_ip])
            f.write(cur_s + "\n")

if __name__ == "__main__":
    """This file is used to test the performance for large nubmer of entries.
    First, randomly create 1M rules and stores them into file fw.csv.
    To generate data, 
    For direction and protocols: 50% for each of their choices
    For port and ip: 50% is a random value, and 50% is random range
    Then test the time for each query
    """
    output_file = "fw2.csv"
    n_line = 1000000
    query_num = 100000
    print("Creating File Now!")
    generate_data(output_file, n_line)

    print("Testing Firewall")
    # Test input processing time
    st_time = time.time()
    fwall = firewall.FireWall("fw2.csv")
    input_processing_time = time.time() - st_time
    query = []
    for i in range(query_num):
        cur_direction = str(random.choice(["inbound", "outbound"]))
        cur_protocol = str(random.choice(["tcp", "udp"]))
        cur_port = random.randint(1, 65535)
        cur_ip = ".".join(str(random.randint(0, 255)) for j in range(4))
        query.append((cur_direction, cur_protocol, cur_port, cur_ip))
    print("input processing time: {}".format(input_processing_time))
    # Test query time
    st_time = time.time()
    for cur_direction, cur_protocol, cur_port, cur_ip in query:
        fwall.accept_packet(cur_direction, cur_protocol, cur_port, cur_ip)
    query_time = (time.time() - st_time) / query_num
    print("average query time: {}".format(query_time))
