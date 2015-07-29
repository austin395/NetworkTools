__author__ = 'austin'

from netaddr import *
import nmap
import time

class HostScanner:
    """
    scans the network for available hosts
    """
    def __init__(self):
        self.resultlist = []
        self.scan()

    def callback_result(self, host):
        print(host)
        self.resultlist.append(host)

    def scan(self):
        print(self.resultlist)
        list = [1, 2, 3, 4, 5, 6]
        for i in list:
            self.callback_result(i)
            print(self.resultlist)
        print(self.resultlist)

def main():
    HostScanner()

if __name__ == "__main__":
    main()
