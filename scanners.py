__author__ = 'austin'

def module_check_r(module):
    """
    Just for debian-based systems like Kali and Ubuntu
    """
    ri = tk.messagebox.askyesno("error",
                                """%s was not found on your system if your an admin and would like to install it
                                press yes""" % module)
    if ri is True:
        if module == 'nmap':
            os.system('gksu apt-get install nmap python-nmap')
        else:
            os.system('gksu pip3 install %s' % module)
    else:
        tk.messagebox.showerror('missing dependencies',
                                'netscanner is closing due to a missing dependency')
        exit(0)

import tkinter as tk
import tkinter.messagebox

try:
    from netaddr import *
except ImportError:
    module_check_r('netaddr')
    from netaddr import *

try:
    import nmap
except:
    module_check_r('nmap')
    import nmap

try:
    from scapy.all import *
except ImportError:
    module_check_r('scapy-python3')
    from scapy.all import *


class Scanners:
    """
    the scanners class will be used to run different scans from the main system or can be used independently
    currently this class is still being built. scan functionality still resides in the Main class
    """
    @staticmethod
    def nma_scan(network_address):

        def callback_result(host, scan_result):
            f = open('results.p', 'ab')
            pickle.dump({host: scan_result}, f)
            f.close()

        nma = nmap.PortScannerAsync()
        Scanners.delete_content('results.p')
        scan_list = list(IPNetwork(network_address))

        start_time = time.time()  # FOR TESTING ... start time
        nma.scan(hosts=network_address, arguments='-T5 -F', callback=callback_result)
        while nma.still_scanning():
            nma.wait(1)

        end_time = time.time()
        print("{} addresses scanned in {} seconds".format(len(scan_list), end_time - start_time))

    @staticmethod
    def concurrent_scapy(network_address):
        addresses = IPNetwork(network_address)
        results = {}
        ports_to_scan = [22, 23, 25, 80, 443]
        for host in addresses:
            if host is not addresses.network or addresses.broadcast:
                resp = sr1(IP(dst=str(host))/ICMP(), timeout=2, verbose=0)
                if (str(type(resp)) == "<type 'NoneType'>"):
                    results[host: 'is down or not responding']
                elif (int(resp.getlayer(ICMP).type) == 3 and int(resp.getlayer(ICMP).code) in [1,2,3,9,10,13]):
                    results[host: 'is blocking icmp']
                else:
                    results[host: 'is up']

    @staticmethod
    def delete_content(name):  # clears the pickle when a new scan starts or when data is explicitly cleared
        with open(name, "w"):
            pass

Scanners.concurrent_scapy('192.168.0.0/30')
