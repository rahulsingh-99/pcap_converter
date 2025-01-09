import os
import sys
import pyshark
import pandas as pd
from multiprocessing import Pool, cpu_count

# Specify the path to TShark if not added to PATH
# print("TSHARK_PATH from environment:", os.getenv('TSHARK_PATH'))

# Fetch the TShark path dynamically
tshark_default_path = os.getenv('TSHARK_PATH')
# if not tshark_default_path:
#     tshark_default_path = input("Please enter the path to TShark (e.g., 'C:\\Program Files\\Wireshark\\tshark.exe'): ")

# print("Using TShark path:", tshark_default_path)
pyshark.tshark.tshark_path = tshark_default_path


def packet_to_dict(packet):
    """Convert packet information to a dictionary."""
    packet_info = {}

    # Extract relevant fields from the packet
    frame_info = getattr(packet, 'frame_info', None)
    if frame_info:
        packet_info.update({
            "Frame Number": getattr(frame_info, 'number', 'N/A'),
            "Arrival Time": getattr(frame_info, 'time', 'N/A'),
            "Frame Length": getattr(frame_info, 'len', 'N/A'),
        })

    eth_layer = getattr(packet, 'eth', None)
    if eth_layer:
        packet_info.update({
            "Ethernet Destination Address": getattr(eth_layer, 'dst', 'N/A'),
            "Ethernet Source Address": getattr(eth_layer, 'src', 'N/A'),
        })

    return packet_info


def process_packet(packet):
    """Wrapper for processing a single packet."""
    try:
        return packet_to_dict(packet)
    except Exception as e:
        print(f"Error processing packet: {e}")
        return {}


def main():
    try:
        script_dir = os.path.dirname(os.path.abspath(__file__))
        upload_dir = os.path.join(script_dir, 'uploads')
        output_dir = os.path.join(script_dir, 'output')

        # Automatically find the first PCAP file in the upload directory
        pcap_file = next(
            (os.path.join(upload_dir, f) for f in os.listdir(upload_dir) if f.endswith('.pcap')), None
        )

        if not pcap_file:
            print("No PCAP file found in the uploads directory.")
            return

        output_file = os.path.join(output_dir, "output_data.xlsx")

        print(f"Trying to open PCAP file at: {pcap_file}")

        # Open the PCAP file
        capture = pyshark.FileCapture(pcap_file)

        # Process packets using multiprocessing
        with Pool(cpu_count()) as pool:
            packets_data = pool.map(process_packet, capture)

        # Convert to DataFrame and save to Excel
        df = pd.DataFrame(packets_data)
        df.to_excel(output_file, index=False)
        print(f"Packet data has been successfully saved to: {output_file}")

    except FileNotFoundError:
        print("Error: The specified PCAP file was not found.")
        sys.exit(1)
    except Exception as e:
        print(f"An error occurred: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
