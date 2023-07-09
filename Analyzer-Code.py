# GUI
import tkinter as tk
from tkinter import ttk
# Network capture
import scapy.all as scapy
# Threading module
import threading
# Collections module
import collections

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
        # If the IP matches the entered sub domain display it along with it's MAC address
        if src_ip[0:len(subdomain)] == subdomain:
            if src_ip not in src_ip_dict:
                src_ip_dict[src_ip] = (src_mac, [dst_ip])
                row = treeV.insert('', index=tk.END, text=src_ip, values=(src_mac,))
                treeV.insert(row, tk.END, text=dst_ip, values=(dst_mac,))
                treeV.pack(fill=tk.X)
            else:
                if dst_ip not in src_ip_dict[src_ip][1]:
                    src_ip_dict[src_ip][1].append(dst_ip)
                    cur_item = treeV.focus()
                    if treeV.item(cur_item)['text'] == src_ip:
                        treeV.insert(cur_item, tk.END, text=dst_ip, values=(dst_mac,))


# Setting key variables
thread = None
stopAnalysing = True
subdomain = ''
src_ip_dict = collections.defaultdict(list)

#------------------ GUI ------------------#
# Creating main window
root = tk.Tk() 
root.geometry('600x600')
root.title('Network Analyzer')

# Creating titles
tk.Label(root, text='Network Analyzer', font='Helvetica 18').pack()
tk.Label(root, text="Enter an IP Subdomain address", font="Helvetica 16").pack()
subdomain_entry = tk.Entry(root)
subdomain_entry.pack(ipady=10, ipadx=40, pady=8)

# Creating the tree view widget
treeV = ttk.Treeview(root, height=400, columns=("mac_address",))
treeV.column("#0", width=150, minwidth=150)
treeV.column("mac_address", width=150, minwidth=150)
treeV.heading("#0", text="IP Address")
treeV.heading("mac_address", text="MAC Address")

# Creating the two buttons
button_frame = tk.Frame(root)
tk.Button(button_frame, text='Start analysing', command=start_button, width=15, font="Helvetica 14").pack(
    side=tk.LEFT)
tk.Button(button_frame, text='Stop analysing', command=stop_button, width=15, font="Helvetica 14").pack(
    side=tk.LEFT)
button_frame.pack(side=tk.BOTTOM, pady=10)

root.mainloop()