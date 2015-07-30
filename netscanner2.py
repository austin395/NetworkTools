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

class NetScanner:
    """
    a simple network scanner using nmap bindings
    """

    def __init__(self):
        # initialize variables
        self.scan_results_ip = 'n/a'
        self.scan_results_hostname = 'n/a'
        self.scan_results_mac = 'n/a'
        self.scan_results_ports = 'n/a'

        self.nma = nmap.PortScannerAsync()
        self.nm = nmap.PortScanner()
        self.root = tk.Tk()
        self.entry_string = tk.StringVar()
        self.dir_checkbutton_state = tk.IntVar()
        self.create_widgets(self.root)
        self.root.title('nmapui.py')
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

        # Help menu
        self.the_about_menu = tk.Menu(self.the_menu_bar, tearoff=0)
        self.the_menu_bar.add_cascade(label="Help", menu=self.the_about_menu)
        self.the_about_menu.add_command(label="About", command=lambda: tk.messagebox.showinfo
            ("About",
            """
            Nmapui
            by: A
            """))

        # code entry
        self.network_label = tk.Label(root, text="network to scan")
        self.network_label.grid(row=0, column=0)
        self.network_entry = tk.Entry(root, width=60, takefocus=True)
        self.network_entry.bind("<Return>",
                                lambda event: self.network_scan(self.network_entry.get()))
        self.network_entry.grid(row=0, column=1, columnspan=2, sticky=tk.N)
        # displays active hosts as result of the last scan
        self.ip_list = tk.Listbox(root)
        self.ip_list.bind('<<Li   stboxSelect>>', lambda event: self.show_host_info())
        self.ip_list.grid(row=1, column=0, rowspan=5, sticky=tk.NS)

        # creates the display image showing information on the selected host
        # IP
        self.IP_info = tk.Label(root, text="IP \t\t: %s" % 'N/A')
        self.IP_info.grid(row=1, column=1, sticky=tk.W)
        # Hostname
        self.Hostname_info = tk.Label(root, text="hostname \t: %s" % 'N/A')
        self.Hostname_info.grid(row=2, column=1, sticky=tk.W)
        # MAC
        self.Mac_info = tk.Label(root, text="MAC Address \t: %s" % 'N/A')
        self.Mac_info.grid(row=3, column=1, sticky=tk.W)
        # Ports
        self.Ports_info = tk.Label(root, text="ports \t\t: %s" % 'N/A')
        self.Ports_info.grid(row=4, column=1, sticky=tk.W)

    def callback_result(self, host, scan_result):
        self.scan_results.append((host, scan_result))
        print(self.scan_results)  # testing...

    def network_scan(self, network_address):
        self.scan_results = []
        self.ip_list.delete(0, tk.END)
        scan_list = list(IPNetwork(network_address))

        start_time = time.time()  # FOR TESTING ... start time
        for i in scan_list:
            self.nma.scan(hosts=str(i), callback=self.callback_result)
            time.sleep(.15)
        while self.nma.still_scanning():
            print('waiting >>>')
            self.nma.wait(2)

        end_time = time.time()

        print("{} addresses scanned in {} seconds".format(len(scan_list), end_time - start_time))
        print(self.scan_results)  # TODO this remains an empty list after the scan finishes, why?

    def show_host_info(self):
        # get relevant data
        self.scan_results_ip = self.ip_list.get(tk.ACTIVE)
        self.scan_results_hostname = self.nma[self.scan_results_ip].hostname()

        if 'vendor' in self.nma[self.scan_results_ip].all_protocols():
            mac_text = ''
            for lmac in self.nma[self.scan_results_ip]['vendor'].keys():
                mac_text = '%s' % lmac
            self.scan_results_mac = mac_text
        else:
            self.scan_results_mac = 'N/A'

        if 'tcp' in self.nma[self.scan_results_ip].all_protocols():
            port_list = []
            port_text = ''
            for lports in self.nma[self.scan_results_ip]['tcp'].keys():
                port_list.append(lports)
            port_list.sort()
            for p in port_list:
                port_text += '\n%s:\tup' % p
            self.scan_results_ports = port_text
        else:
            self.scan_results_ports = 'N/A'

        for proto in self.nma[self.scan_results_ip].all_protocols():
            print(proto)

        # update GUI
        self.IP_info.config(text='IP \t\t: %s' % self.scan_results_ip)
        self.Hostname_info.config(text='Hostname \t: %s' % self.scan_results_hostname)
        self.Mac_info.config(text='MAC Address \t: %s' % self.scan_results_mac)
        self.Ports_info.config(text='Ports: %s' % self.scan_results_ports)
        self.root.update_idletasks()


def main():
    NetScanner()

if __name__ == "__main__":
    main()
