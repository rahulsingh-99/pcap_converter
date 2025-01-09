import pyshark

# Define the path to the PCAP file
pcap_file = input("Please enter the path to the PCAP file: ")

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
        print(f"Arrival Time: {getattr(frame_info, 'time', 'N/A')}")
        print(f"Arrival time (UTC): {getattr(frame_info, 'time_utc', 'N/A')} UTC")
        print(f"Arrival Time (Local): {getattr(frame_info, 'time_epoch', 'N/A')} seconds")
        print(f"Time Shift for This Packet: {getattr(frame_info, 'offset_shift', 'N/A')} seconds")
        print(f"Time delta from captured frame: {getattr(frame_info, 'time_delta', 'N/A')} seconds")
        print(f"Time delta displayed: {getattr(frame_info, 'time_delta_displayed', 'N/A')} seconds")
        print(f"Time since first frame: {getattr(frame_info, 'time_relative', 'N/A')} seconds")
        print(f"Frame Number: {getattr(frame_info, 'number', 'N/A')}")
        print(f"Frame Length: {getattr(frame_info, 'len', 'N/A')} bytes")
        print(f"Captured Length: {getattr(frame_info, 'cap_len', 'N/A')} bytes")
        print(f"Frame is marked: {getattr(frame_info, 'marked', 'N/A')}")
        print(f"Frame is ignored: {getattr(frame_info, 'ignored', 'N/A')}")
        print(f"Frame protocols: {getattr(frame_info, 'protocols', 'N/A')}")
    else:
        print("Frame info not available")

    # Ethernet II fields
    eth_layer = getattr(packet, 'eth', None)
    if eth_layer:
        print("\nEthernet II Layer:")
        print(f"Destination Address: {getattr(eth_layer, 'dst_oui_resolved', '') + getattr(eth_layer, 'dst', 'N/A')}")
        print(f"Destination LG bit: {getattr(eth_layer, 'dst_lg', 'N/A')}")
        print(f"Destination IG bit: {getattr(eth_layer, 'dst_ig', 'N/A')}")
        print(f"Source Address: {getattr(eth_layer, 'src_oui_resolved', '') + getattr(eth_layer, 'src', 'N/A')}")
        print(f"Source LG bit: {getattr(eth_layer, 'src_lg', 'N/A')}")
        print(f"Type: {getattr(eth_layer, 'type', 'N/A')}")
        print(f"Stream Index: {getattr(eth_layer, 'stream', 'N/A')}")
    else:
        print("Ethernet II layer not available")

    # VLAN fields
    vlan_layer = getattr(packet, 'vlan', None)
    if vlan_layer:
        print("\n802.1Q Virtual LAN Layer:")
        print(f"Priority: {getattr(vlan_layer, 'priority', 'N/A')}")
        print(f"DEI: {getattr(vlan_layer, 'dei', 'N/A')}")
        print(f"ID: {getattr(vlan_layer, 'id', 'N/A')}")
        print(f"Type: {getattr(vlan_layer, 'type', 'N/A')}")
        print(f"VLAN Type: {getattr(vlan_layer, 'etype', 'N/A')}")
    else:
        print("VLAN layer not available")

    # eCPRI fields
    ecpri_layer = getattr(packet, 'ecpri', None)
    if ecpri_layer:
        print("\neCPRI Common Header:")
        print(f"Header: {getattr(ecpri_layer, 'header', 'N/A')}")
        print(f"Protocol Revision: {getattr(ecpri_layer, 'revision', 'N/A')}")
        print(f"Reserved Bits: {getattr(ecpri_layer, 'reserved', 'N/A')}")
        print(f"C-bit: {getattr(ecpri_layer, 'cbit', 'N/A')}")
        print(f"eCPRI Length: {getattr(ecpri_layer, 'length', 'N/A')}")
        print(f"Message Type: {getattr(ecpri_layer, 'type', 'N/A')}")
        print(f"Payload Size: {getattr(ecpri_layer, 'size', 'N/A')}")
        print(f"eCPRI Payload: {getattr(ecpri_layer, 'payload', 'N/A')}")
    else:
        print("eCPRI layer not available")

    # O-RAN Fronthaul CUS fields
    oran_layer = getattr(packet, 'oran_fh_cus', None)
    if oran_layer:
        print("\nO-RAN Fronthaul CUS Layer:")
        print("\neCPRI RTCID:")
        print(f"DU Port ID: {getattr(oran_layer, 'du_port_id', 'N/A')}")
        print(f"BandSector ID: {getattr(oran_layer, 'bandsector_id', 'N/A')}")
        print(f"CC ID: {getattr(oran_layer, 'cc_id', 'N/A')}")
        print(f"RU Port ID: {getattr(oran_layer, 'ru_port_id', 'N/A')}")
        print(f"c_eAxC_ID: {getattr(oran_layer, 'c_eaxc_id', 'N/A')}")

        # eCPRI SEQID fields
        print('\neCPRI SEQID:')
        print(f"Sequence ID: {getattr(oran_layer, 'sequence_id', 'N/A')}")
        print(f"E-Bit: {getattr(oran_layer, 'e_bit', 'N/A')}")
        print(f"Subsequence ID: {getattr(oran_layer, 'subsequence_id', 'N/A')}")
        
        # C-PLANE fields
        print("\nC-Plane Section Type:")
        print(f"Data Direction: {getattr(oran_layer, 'data_direction', 'N/A')}")
        print(f"Payload Version: {getattr(oran_layer, 'payloadversion', 'N/A')}")
        print(f"Filter Index: {getattr(oran_layer, 'filterindex', 'N/A')}")
        print(f"Frame ID: {getattr(oran_layer, 'frameid', 'N/A')}")
        print(f"Subframe ID: {getattr(oran_layer, 'subframe_id', 'N/A')}")
        print(f"Slot ID: {getattr(oran_layer, 'slotid', 'N/A')}")
        print(f"Start Symbol: {getattr(oran_layer, 'startsymbolid', 'N/A')}")
        print(f"Symbol Identifier: {getattr(oran_layer, 'symbolid', 'N/A')}")
        print(f"refA: {getattr(oran_layer, 'refa', 'N/A')}")
        print(f"Number Of Sections: {getattr(oran_layer, 'numberofsections', 'N/A')}")
        print(f"Section Type: {getattr(oran_layer, 'sectiontype', 'N/A')}")
        print(f"Section ID: {getattr(oran_layer, 'sectionid', 'N/A')}")
        print(f"rb: {getattr(oran_layer, 'rb', 'N/A')}")
        print(f"SymInc: {getattr(oran_layer, 'syminc', 'N/A')}")
        print(f"Start Prbu: {getattr(oran_layer, 'startprbu', 'N/A')}")
        print(f"Num Prbu: {getattr(oran_layer, 'numprbu', 'N/A')}")

        # User Data Compression Header fields
        print("\nudCompHdr:")
        print(f"User Data IQ width: {getattr(oran_layer, 'udcomphdrwidth', 'N/A')}")
        print(f"User Data Compression Method: {getattr(oran_layer, 'udcomphdrmeth', 'N/A')}")
        print(f"Reserved8: {getattr(oran_layer, 'reserved8', 'N/A')}")
        print(f"Prb: {getattr(oran_layer, 'prb', 'N/A')}")
        print(f"RE Mask: {getattr(oran_layer, 'remask', 'N/A')}")
        print(f"Number of Symbols: {getattr(oran_layer, 'numsymbol', 'N/A')}")
        print(f"Extension Flag: {getattr(oran_layer, 'ef', 'N/A')}")
        
        # Beam field
        print("\nBeam_ID:")
        print(f"Beam ID: {getattr(oran_layer, 'beamid', 'N/A')}")
        
        # PRB fields
        print("\nPRB:")
        print(f"UdCompparam: {getattr(oran_layer, 'udcompparam', 'N/A')}")
        print(f"Reserved Bits: {getattr(oran_layer, 'reserved8', 'N/A')}")
        print(f"Reserved Bits: {getattr(oran_layer, 'reserved', 'N/A')}")
        print(f"Exponent: {getattr(oran_layer, 'exponent', 'N/A')}")
        print(f"IQ User Data: {getattr(oran_layer, 'iq_user_data', 'N/A')}")
        print(f"I sample: {getattr(oran_layer, 'isample', 'N/A')}")
        print(f"Q sample: {getattr(oran_layer, 'qsample', 'N/A')}")
        print(f"")
    else:
        print("O-RAN Fronthaul CUS layer not available")

    # Malformed fields
    malformed_layer = getattr(packet, '_ws.malformed', None)
    if malformed_layer:
        print("\n_ws.malformed:")
        print(f"Expert: {getattr(malformed_layer, '_ws_expert', 'N/A')}")
        print(f"Message: {getattr(malformed_layer, '_ws_expert_message', 'N/A')}")
        print(f"Severity: {getattr(malformed_layer, '_ws_expert_severity', 'N/A')}")
        print(f"Group: {getattr(malformed_layer, '_ws_expert_group', 'N/A')}")
        print(f"Raw Mode: {getattr(malformed_layer, 'raw_mode', 'N/A')}")
    else:
        print("_ws.malformed layer not available")
    
