# Network-Analyzer

The Network Analyzer application is a Python-based network tool that allows you to capture and analyze network packets within a specified IP subdomain. The application leverages the Scapy library for packet sniffing and provides a Graphical User Interface (GUI) using the Tkinter Python module.

In the next few months, this project will be expanded to encompass additional network analysis, as well as displaying the MAC addresses, protocols and payload data for HTTP packets.

## Features
- Capture network packets within a specified IP subdomain.
- Display the source and destination IP addresses in a neat user interface.
- Start and stop packet analysing with the click of a button.
- Real-time updates of captured packets.

## Prerequisites
    Python 3.x
    Scapy library (pip install scapy)
    Tkinter library (included with Python)

## Usage
1. Clone the repository or download the project files.
2. Run the Analyzer-Code.py script.
3. Enter the IP subdomain you want to monitor in the application's GUI.
4. Click the "Start analysing" button to start capturing packets.
5. The captured IP addresses of these packets will be displayed in the GUI.
6. Click the "Stop analysing" button to stop packet capture.

## Notes
- The application uses the Scapy library for packet sniffing, which requires appropriate privileges (e.g., running as an administrator or using sudo on Unix-based systems) to access network interfaces and capture packets.
- The captured packets are filtered based on the specified IP subdomain to focus on the desired network traffic.
- Currently, the application analyzes HTTP packets to extract payload data. Additional protocols and analysis will be added in future commits.
