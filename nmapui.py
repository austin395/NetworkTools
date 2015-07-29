__author__ = 'austin'

import tkinter as tk
import nmap
import tkinter.messagebox
from tkinter import ttk
import time


class DrawGui():
    """
    Draws the main GUI
    """
    def __init__(self):
        self.root = tk.Tk()
        self.entry_string = tk.StringVar()
        self.dir_checkbutton_state = tk.IntVar()
        self.create_widgets(self.root)
        self.root.title('nmapui.py')
        self.root.geometry("765x480")
        self.root.mainloop()

        # initialize variables
        self.scan_results_ip = 'n/a'
        self.scan_results_hostname = 'n/a'
        self.scan_results_mac = 'n/a'
        self.scan_results_ports = 'n/a'

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

        # Sort by sub-menu
        # Each sort option must pass a 'sortby' value which must then be created in self.build_dir_list
        # and class 'DirFuncs'.
        self.the_sort_menu = tk.Menu(root, tearoff=0)

        # View menu
        self.the_view_menu = tk.Menu(self.the_menu_bar, tearoff=0)
        self.the_menu_bar.add_cascade(label="View", menu=self.the_view_menu)

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
        self.ip_list.bind('<<ListboxSelect>>', lambda event: self.show_host_info())
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


        # Right click menu on directory list
        self.right_click_menu = tk.Menu(self.root, tearoff=0)  # Creates the right click menu in directory list

    def network_scan(self, network_address):
        self.ip_list.delete(0, tk.END)
        self.nm = nmap.PortScanner()
        self.nm.scan(hosts=network_address)
        for host in self.nm.all_hosts():
            self.ip_list.insert(tk.END, host)
        print('done')

    def show_host_info(self):
        # get relevant data
        self.scan_results_ip = self.ip_list.get(tk.ACTIVE)
        self.scan_results_hostname = self.nm[self.scan_results_ip].hostname()

        if 'vendor' in self.nm[self.scan_results_ip].all_protocols():
            mac_text = ''
            for lmac in self.nm[self.scan_results_ip]['vendor'].keys():
                mac_text = '%s' % lmac
            self.scan_results_mac = mac_text
        else:
            self.scan_results_mac = 'N/A'

        if 'tcp' in self.nm[self.scan_results_ip].all_protocols():
            port_list = []
            port_text = ''
            for lports in self.nm[self.scan_results_ip]['tcp'].keys():
                port_list.append(lports)
            port_list.sort()
            for p in port_list:
                port_text += '\n%s:\tup' % p
            self.scan_results_ports = port_text
        else:
            self.scan_results_ports = 'N/A'

        for proto in self.nm[self.scan_results_ip].all_protocols():
            print(proto)

        # update GUI
        self.IP_info.config(text='IP \t\t: %s' % self.scan_results_ip)
        self.Hostname_info.config(text='Hostname \t: %s' % self.scan_results_hostname)
        self.Mac_info.config(text='MAC Address \t: %s' % self.scan_results_mac)
        self.Ports_info.config(text='Ports: %s' % self.scan_results_ports)
        self.root.update_idletasks()


def main():
    DrawGui()

if __name__ == "__main__":
    main()
