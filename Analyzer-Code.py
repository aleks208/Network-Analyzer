# GUI
import tkinter as tk
from tkinter import ttk
# Network capture
import scapy.all as scapy
# Threading module
import threading
# Collections module
import collections
# For MAC Vendors API
import requests

# Button used to start scanning the network subdomain
def start_button():
    global stopAnalysing
    global thread
    global subdomain
    subdomain = subdomain_entry.get()
    # If the thread is not set or not alive, then we shouldn't stop looking for packets
    if (thread is None) or (not thread.is_alive()):
        stopAnalysing = False
        thread = threading.Thread(target=sniffing)
        thread.start()

# Button used to stop scanning the network
def stop_button():
    global stopAnalysing
    stopAnalysing = True

# Sniffing the network
def sniffing():
    scapy.sniff(prn=find_ips, stop_filter=stop_sniffing)

# Returns the stopAnalysing variable
def stop_sniffing(packet):
    global stopAnalysing
    return stopAnalysing

# Using the MacVendors API, finds the vendor for give MAC address
def get_mac_vendors(mac_address):
    url = f"https://api.macvendors.com/{mac_address}"
    response = requests.get(url)
    if response.status_code == 200:
        return response.text.strip()
    else:
        return "Unknown"

# Finds all the ip addresses on the network subdomain
def find_ips(packet):
    global src_ip_dict
    global treeV
    global subdomain
    # If packet contains IPs
    if 'IP' in packet:
        # Get IP addresses
        src_ip = packet['IP'].src
        dst_ip = packet['IP'].dst
        # Get MAC addresses
        src_mac = packet['Ether'].src
        dst_mac = packet['Ether'].dst
        # Get Protocol and Port
        protocol = packet['IP'].proto
        src_port = packet['IP'].sport
        dst_port = packet['IP'].dport
        # If the IP matches the entered sub domain display it along with it's MAC address
        if src_ip[0:len(subdomain)] == subdomain:
            if src_ip not in src_ip_dict:
                src_ip_dict[src_ip] = (src_mac, [dst_ip])
                vendor = get_mac_vendors(src_mac)
                src_mac = src_mac + " which is " + vendor
                row = treeV.insert('', index=tk.END, text=src_ip, values=(src_mac, protocol, src_port))
                vendor = get_mac_vendors(dst_mac)
                dst_mac = dst_mac + " which is " + vendor
                treeV.insert(row, tk.END, text=dst_ip, values=(dst_mac, protocol, dst_port))
                treeV.pack(fill=tk.X)
            else:
                if dst_ip not in src_ip_dict[src_ip][1]:
                    vendor = get_mac_vendors(dst_mac)
                    dst_mac = dst_mac + " which is " + vendor
                    src_ip_dict[src_ip][1].append(dst_ip)
                    cur_item = treeV.focus()
                    if treeV.item(cur_item)['text'] == src_ip:
                        treeV.insert(cur_item, tk.END, text=dst_ip, values=(dst_mac, protocol, dst_port))

# Setting key variables
thread = None
stopAnalysing = True
subdomain = ''
src_ip_dict = collections.defaultdict(list)

#------------------------------------ GUI ------------------------------------#
# Creating main window
root = tk.Tk() 
root.geometry('650x600')
root.title('Network Analyzer')
root.configure(background='#F5F5F5')

# Creating titles
tk.Label(root, text='Network Analyzer', font='Inconsolata 20 bold', fg='#006400', bg='#F5F5F5').pack()
tk.Label(root, text="Enter an IP Subdomain address", font="Inconsolata 16", fg='#228B22', bg='#F5F5F5').pack()

# Creatinng the entry box
subdomain_entry = tk.Entry(root, justify='center', font='Inconsolata 13')
subdomain_entry.pack(ipady=5, ipadx=10)

# Creating the two buttons
button_frame = tk.Frame(root)
tk.Button(button_frame, text='Start', command=start_button, width=6, font="Inconsolata 14", fg='white', bg='#006400').pack(
    side=tk.LEFT)
tk.Button(button_frame, text='Stop', command=stop_button, width=6, font="Inconsolata 14", fg='white', bg='#006400').pack(
    side=tk.LEFT)
button_frame.pack(pady=10)

# Creating the tree view widget
treeV = ttk.Treeview(root, height=350, columns=("mac_address", "protocol", "port"))
treeV.column("#0", width=30, minwidth=30, anchor="center")
treeV.column("mac_address", width=170, minwidth=170, anchor="center")
treeV.column("protocol", width=15, minwidth=15, anchor="center")
treeV.column("port", width=15, minwidth=15, anchor="center")
treeV.heading("#0", text="IP Address")
treeV.heading("mac_address", text="MAC Address")
treeV.heading("protocol", text="Protocol")
treeV.heading("port", text="Port")
style = ttk.Style(root)
style.theme_use("clam")
ttk.Style().configure("Treeview", background="#98FF98", foreground="black", fieldbackground="#98FF98", font="Inconsolata 10")

root.mainloop()