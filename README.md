# Network-Analyzer

The Network Analyzer application is a Python-based network tool that allows you to capture and analyze network packets within a specified IP subdomain. The application leverages the Scapy library for packet sniffing and provides a graphical user interface (GUI) using the Tkinter and ttk modules.

In the next few months, this project will be expanded to encompass additional network analysis.

## Features
- Capture network packets within a specified IP subdomain.
- Display the source and destination IP addresses, MAC addresses, protocols, and payload data (for HTTP packets) in a GUI.
- Start and stop packet sniffing with the click of a button.
- Real-time updates of captured packets in the GUI.

## Prerequisites

    Python 3.x
    Scapy library (pip install scapy)
    Tkinter library (included with Python)

## Usage
1. Clone the repository or download the project files.
2. Install the required dependencies using pip install -r requirements.txt.
3. Run the packet_sniffer.py script.
4. Enter the IP subdomain you want to monitor in the application's GUI.
5. Click the "Start sniffing" button to start capturing packets.
6. The captured packets will be displayed in the GUI, including IP addresses, MAC addresses, protocols, and payload data (for HTTP packets).
7. Click the "Stop sniffing" button to stop packet capture.

## Notes
- The application uses the Scapy library for packet sniffing, which requires appropriate privileges (e.g., running as an administrator or using sudo on Unix-based systems) to access network interfaces and capture packets.
- The captured packets are filtered based on the specified IP subdomain to focus on the desired network traffic.
- Currently, the application analyzes HTTP packets to extract payload data. Additional protocols and analysis can be added as needed

