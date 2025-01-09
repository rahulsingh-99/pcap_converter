import pyshark

# Define the path to the PCAP file
pcap_file = r'"C:\Users\Rahul Singh\Documents\pacap_project\transmitter_uplane_dl_only_5g_nr2_1cc_400MHz_TM1p1_10ms_4pcap.pcap"'

# Open the PCAP file
capture = pyshark.FileCapture(pcap_file)

# Loop through each packet in the PCAP file
for packet in capture:
    print(f"\n--- Frame {packet.number} ---")

    # Frame fields
    frame_info = getattr(packet, 'frame_info', None)
    if frame_info:
        print("\nFrame Info:")
        print(f"Encapsulation Type: {getattr(frame_info, 'encap_type', 'N/A')}")
