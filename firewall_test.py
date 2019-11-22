import unittest
import firewall

class FireWallTest(unittest.TestCase):
    """ Perform Unit Test. It creates the firewall that loads 
    the hardcoded input file "fw.csv", and test whether the result 
    is correct given the file rules.
    """
    def __init__(self, *args, **argv):
        super().__init__(*args, **argv)
        filename = "fw.csv"
        self.fwall = firewall.FireWall(filename)
    
    def test_ip_to_int(self):
        self.assertEqual(firewall._ip_to_int("0.0.0.0"), 0)
        self.assertEqual(firewall._ip_to_int("1.0.0.0"), 16777216)
        self.assertEqual(firewall._ip_to_int("1.1.0.0"), 16842752)
        self.assertEqual(firewall._ip_to_int("24.0.123.0"), 402684672)
        self.assertEqual(firewall._ip_to_int("255.255.255.255"), 4294967295)
    
    def test_valid_packet(self):
        self.assertTrue(self.fwall.accept_packet("outbound", "udp", 65535, "255.255.255.255"))
        self.assertTrue(self.fwall.accept_packet("inbound", "tcp", 37, "192.168.1.1"))
        self.assertTrue(self.fwall.accept_packet("inbound", "udp", 41, "1.168.1.1"))
        self.assertTrue(self.fwall.accept_packet("outbound", "tcp", 15, "192.168.1.1"))
        self.assertTrue(self.fwall.accept_packet("outbound", "tcp", 1234, "0.0.255.255"))
        self.assertTrue(self.fwall.accept_packet("outbound", "tcp", 4568, "255.255.0.0"))
        self.assertTrue(self.fwall.accept_packet("outbound", "tcp", 1199, "2.0.1.1"))
    
    def test_invalid_packet(self):
        self.assertFalse(self.fwall.accept_packet("inbound", "tcp", 0, "0.0.0.0"))
        self.assertFalse(self.fwall.accept_packet("inbound", "tcp", 25023, "192.168.1.1"))
        self.assertFalse(self.fwall.accept_packet("inbound", "udp", 102, "13.168.1.1"))
        self.assertFalse(self.fwall.accept_packet("outbound", "tcp", 25, "192.168.11.1"))


if __name__ == "__main__":
    unittest.main()
