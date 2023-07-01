# GUI
import tkinter as tk
from tkinter import ttk
# Network capture
import scapy.all as scapy
# Threading module
import threading
# Collections module
import collections

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

def stop_button():
    global stopAnalysing
    stopAnalysing = True

def sniffing():
    scapy.sniff(prn=find_ips, stop_filter=stop_sniffing)

def stop_sniffing(packet):
    global stopAnalysing
    return stopAnalysing

def find_ips(packet):
    global src_ip_dict
    global treeV
    global subdomain

    if 'IP' in packet:
        src_ip = packet['IP'].src
        dst_ip = packet['IP'].dst
        if src_ip[0:len(subdomain)] == subdomain:
            if src_ip not in src_ip_dict:
                src_ip_dict[src_ip].append(dst_ip)

                row = treeV.insert('', index=tk.END, text=src_ip)
                treeV.insert(row, tk.END, text=dst_ip)
                treeV.pack(fill=tk.X)

            else:
                if dst_ip not in src_ip_dict[src_ip]:
                    src_ip_dict[src_ip].append(dst_ip)

                    cur_item = treeV.focus()

                    if treeV.item(cur_item)['text'] == src_ip:
                        treeV.insert(cur_item, tk.END, text=dst_ip)

thread = None
stopAnalysing = True
subdomain = ''

src_ip_dict = collections.defaultdict(list)

# GUI
root = tk.Tk()  # created main window
root.geometry('600x600')
root.title('Network Analyzer')

tk.Label(root, text='Network Analyzer', font='Helvetica 20 bold').pack()
tk.Label(root, text="Enter an IP Subdomain address", font="Helvetica 16").pack()
subdomain_entry = tk.Entry(root)
subdomain_entry.pack(ipady=5, ipadx=50, pady=10)

treeV = ttk.Treeview(root, height=400)
treeV.column('#0')

button_frame = tk.Frame(root)
tk.Button(button_frame, text='Start sniffing', command=start_button, width=15, font="Helvetica 16").pack(
    side=tk.LEFT)
tk.Button(button_frame, text='Stop sniffing', command=stop_button, width=15, font="Helvetica 16").pack(
    side=tk.LEFT)
button_frame.pack(side=tk.BOTTOM, pady=10)

root.mainloop()