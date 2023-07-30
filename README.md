# Network-Analyzer

The Network Analyzer application is a Python-based network tool that allows you to capture and analyze network packets within a specified IP subdomain. The application leverages the Scapy library for packet sniffing and provides a Graphical User Interface (GUI) using the Tkinter Python module.

## Features
- Live capture of network packets within a specified IP subdomain.
- Display of captured packets in a user-friendly tree view.
- Automatic lookup of MAC address vendors using the MacVendors API.
- Start and stop packet analysing with the click of a button.
- Real-time updates of captured packets.

## Prerequisites
    Python 3.x
    Scapy library (pip install scapy)
    Tkinter library (included with Python)
    Requests library (pip install requests)

## Usage
1. Clone the repository or download the project files.
2. Run the Analyzer-Code.py script.
3. Enter the IP subdomain you want to monitor in the application's GUI.
4. Click the "Start analysing" button to start capturing packets.
5. The captured packets will be displayed in a tree view widget showing IP addresses, MAC addresses, protocols, and ports.
6. Click the "Stop analysing" button to stop packet capture.

## Notes
- The application uses the Scapy library for packet sniffing, which requires appropriate privileges (e.g., running as an administrator or using sudo on Unix-based systems) to access network interfaces and capture packets.
- The captured packets are filtered based on the specified IP subdomain to focus on the desired network traffic.
- Network packet capture should only be done on networks that you have the proper authorisation to monitor.

## Disclaimer
This program is intended for educational and informational purposes only. The author is not responsible for any misuse of the program or any consequences that arise from using it.
Ensure that you have the proper authorisation before scanning any network.
