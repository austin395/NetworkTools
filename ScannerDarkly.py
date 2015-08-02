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

import os
import tkinter as tk
import tkinter.messagebox
import time
import pickle
import socket
import sys
import subprocess
from threading import Thread
from queue import Queue, Empty


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

class Main:
    """
    a simple network scanner using nmap bindings
    """

    def __init__(self):
        self.nma = nmap.PortScannerAsync()
        self.nm = nmap.PortScanner()
        self.root = tk.Tk()
        self.entry_string = tk.StringVar()
        self.dir_checkbutton_state = tk.IntVar()
        self.create_widgets(self.root)
        self.root.title('Scanner Darkly')
        self.root.geometry("765x480")
        self.root.mainloop()

    def create_widgets(self, root):
        """
        Draws the main window and the majority of GUI widgets
        """

        # Menu bar
        self.the_menu_bar = tk.Menu(self.root)
        self.root.config(menu=self.the_menu_bar)
        self.top = self.root.winfo_toplevel()
        self.top.rowconfigure(5, weight=1)
        self.top.columnconfigure(4, weight=1)
        self.root.rowconfigure(5, weight=1)
        self.root.columnconfigure(4, weight=1)

        # File menu
        self.the_file_menu = tk.Menu(self.the_menu_bar, tearoff=0)
        self.the_menu_bar.add_cascade(label="File", menu=self.the_file_menu)
        self.the_file_menu.add_command(label="Exit", command=root.quit)
        self.the_file_menu.add_command(label="Export results", command=Main.export_to)

        # Help menu
        self.the_about_menu = tk.Menu(self.the_menu_bar, tearoff=0)
        self.the_menu_bar.add_cascade(label="Help", menu=self.the_about_menu)
        self.the_about_menu.add_command(label="About", command=lambda: tk.messagebox.showinfo
            ("About",
            """
            Scanner Darkly
            by: A
            a graphical network scanner built on top of the nmap scanner
            """))

        # code entry
        self.network_label = tk.Label(root, text="network to scan")
        self.network_label.grid(row=0, column=0)
        self.network_entry = tk.Entry(root, width=60, takefocus=True)
        self.network_entry.bind("<Return>",
                                lambda event: self.nma_scan(self.network_entry.get()))
        self.network_entry.grid(row=0, column=1, columnspan=2, sticky=tk.N)
        # displays active hosts
        self.ip_list = tk.Listbox(root)
        self.ip_list.bind('<<ListboxSelect>>', lambda event: self.show_host_info())
        self.ip_list.grid(row=1, column=0, rowspan=5, sticky=tk.NS)

        try:    # creates a pickle file if one does not exist
            self.post_scan()
        except FileNotFoundError:
            create = open('results.p', 'w')
            create.close()
            self.post_scan()

        # creates the display image showing information on the selected host
        # IP
        self.IP_info = tk.Label(root, text="IP \t\t: N/A")
        self.IP_info.grid(row=1, column=1, sticky=tk.W)
        # Hostname
        self.Hostname_info = tk.Label(root, text="hostname \t: N/A")
        self.Hostname_info.grid(row=2, column=1, sticky=tk.W)
        # MAC
        self.Mac_info = tk.Label(root, text="MAC Address \t: N/A")
        self.Mac_info.grid(row=3, column=1, sticky=tk.W)
        # time scanned
        self.time_info = tk.Label(root, text="time scanned \t: N/A")
        self.time_info.grid(row=4, column=1, sticky=tk.W)
        # Ports
        self.Ports_info = tk.Label(root, text="ports \t\t: N/A")
        self.Ports_info.grid(row=5, column=1, sticky=tk.NW)

        try:    # handles error caused by no previous scans
            self.show_host_info()
        except KeyError:
            pass

    def callback_result(self, host, scan_result):
        f = open('results.p', 'ab')
        pickle.dump({host: scan_result}, f)
        f.close()

    def nma_scan(self, network_address):
        self.delete_content('results.p')
        scan_list = list(IPNetwork(network_address))

        start_time = time.time()  # FOR TESTING ... start time
        self.nma.scan(hosts=network_address, arguments='-T5 -F', callback=self.callback_result)
        while self.nma.still_scanning():
            self.nma.wait(1)

        end_time = time.time()
        print("{} addresses scanned in {} seconds".format(len(scan_list), end_time - start_time))
        self.post_scan()

    @staticmethod
    def run_new_scan(scan_type):
        # TODO rewrite to run scan from scanners class and remove scan from this class
        try:
            subprocess.check_call([sys.executable, 'sudo scanners.py', scan_type])
        except:
            print('an error occurred')

    def show_host_info(self):  # gets data about the currently selected host and pushes that data to the gui
        scan_results = {}
        # loads the pickled data into scan_results
        f = open('results.p', 'rb')
        while True:
            try:
                scan_results.update(pickle.load(f))
            except EOFError:
                break
        f.close()
        # ipv4 address
        ip = str(self.ip_list.get(tk.ACTIVE))
        if ip is '':  # prevents crash when selecting and empty object in the listbox
            return
        # hostname
        hostname = scan_results[ip]['scan'][ip]['hostname']
        # mac address
        if 'vendor' in scan_results[ip]['scan'][ip]:

            mac = scan_results[ip]['scan'][ip]['vendor']
        else:
            mac = 'N/A'
        # timestamp
        # port status
        ports = {}
        port_text = ''
        if 'tcp' in scan_results[ip]['scan'][ip]:
            for port in scan_results[ip]['scan'][ip]['tcp']:
                ports[port] = scan_results[ip]['scan'][ip]['tcp'][port]['name']
            for p in ports:
                port_text += '\n{}/{}\tis up'.format(p, ports[p])
        # update GUI
        self.IP_info.config(text='IP \t\t: %s' % ip)
        self.Hostname_info.config(text='Hostname \t: %s' % hostname)
        self.Mac_info.config(text='MAC Address \t: %s' % mac)
        self.Ports_info.config(text='Ports \t\t: %s' % port_text)
        self.root.update_idletasks()

    @staticmethod
    def delete_content(fname):  # clears the pickle when a new scan starts or when data is explicitly cleared
        with open(fname, "w"):
            pass

    def post_scan(self):
        #  handles updating the listbox post scan, this was modularized for future addition of other scan methods
        self.ip_list.delete(0, tk.END)
        scan_results = {}
        f = open('results.p', 'rb')
        while True:
            try:
                scan_results.update(pickle.load(f))
            except EOFError:
                break
        f.close()
        for key, value in sorted(scan_results.items(), key=lambda item: socket.inet_aton(item[0])):
            if scan_results[key]['nmap']['scanstats']['uphosts'] is '1':
                self.ip_list.insert(tk.END, key)  # TODO some results don't seem to populate
                print(key)
            else:
                print(value)
        self.ip_list.update()

    @staticmethod
    def export_to():
        try:
            subprocess.check_call([sys.executable, 'export.py'])
        except:
            print('unexpected error')

def main():
    Main()

if __name__ == "__main__":
    main()
