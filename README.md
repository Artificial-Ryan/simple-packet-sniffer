# Simple Packet Sniffer and Analyzer

This is a basic Python-based packet sniffer and analyzer built using the `scapy` library. It captures network traffic, extracts key information (source/destination IPs, ports, protocols), and saves the captured packets to a `.pcap` file for further analysis.

## Features

- Captures network packets.
- Extracts and displays source IP, destination IP, protocol, and port information (for TCP/UDP).
- Shows a snippet of the packet payload.
- Filters packets (currently set to IP traffic).
- Saves captured packets to a `.pcap` file.

## Author

- Peter (Ryan) Harp

## Installation

1.  **Clone the repository:**

    ```bash
    git clone <your-repo-url>
    cd packet_sniffer
    ```

2.  **Install dependencies:**

    ```bash
    pip install -r requirements.txt
    ```

    *Note: You might need to run `sudo pip install scapy` if you encounter permission errors during sniffing, as `scapy` often requires global installation for elevated privileges.*

## Usage

To run the packet sniffer, navigate to the project directory and execute the script with `sudo`:

```bash
sudo python3 packet_sniffer.py
```

The script will capture 10 IP packets and save them to `captured_packets.pcap` in the same directory.

## Customization

- **Packet Count:** Modify the `count` parameter in the `sniff()` function in `packet_sniffer.py` to capture more or fewer packets.
- **Filters:** Change the `filter` parameter in the `sniff()` function to capture specific types of traffic (e.g., `tcp`, `udp`, `port 80`, `host 192.168.1.1`). Refer to [BPF syntax](https://biot.com/capstats/bpf.html) for more filtering options.
- **Output File:** Change the `output_file` variable in `packet_sniffer.py` to save the captured packets to a different file name.

## Contributing

Feel free to fork this repository, make improvements, and submit pull requests. Contributions are always welcome!
