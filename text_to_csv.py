import pyshark
import os
import nest_asyncio
from multiprocessing import Pool, cpu_count
from itertools import islice

# Allow multiple asyncio event loops
nest_asyncio.apply()

# Function to process a chunk of packets
def process_packet_chunk(chunk_info):
    chunk, output_dir = chunk_info
    results = []
    for packet in chunk:
        try:
            frame_file_path = os.path.join(output_dir, f"frame_{packet.number}.txt")
            with open(frame_file_path, "w") as output_file:
                output_file.write(f"\n--- Frame {packet.number} ---\n")

                # O-RAN Fronthaul CUS fields
                oran_layer = getattr(packet, 'oran_fh_cus', None)
                if oran_layer:
                    output_file.write(f"Oran layer: {oran_layer}\n")
                    if hasattr(oran_layer, 'fields'):
                        for field in oran_layer.fields:
                            output_file.write(f"{field.name}: {field.showname_value}\n")
        except Exception as e:
            results.append(f"Error processing packet {packet.number}: {e}")
    return results

# Function to chunk the iterable
def chunked(iterable, size):
    iterator = iter(iterable)
    for first in iterator:
        yield [first, *islice(iterator, size - 1)]

# Function to process the PCAP file and write the output to text files
def process_pcap_files(pcap_file, output_dir, chunk_size=50, max_packets=500):
    # Ensure the output directory exists
    if not os.path.exists(output_dir):
        os.makedirs(output_dir, exist_ok=True)
        print(f"Created output directory: {output_dir}")
    else:
        print(f"Output directory exists: {output_dir}")

    # Open the PCAP file
    print(f"Looking for PCAP file at: {pcap_file}")
    capture = pyshark.FileCapture(pcap_file)

    # Limit packets for processing
    limited_packets = list(islice(capture, max_packets))


    # Process packets in chunks
    packet_chunks = chunked(limited_packets, chunk_size)
    chunk_info_list = [(chunk, output_dir) for chunk in packet_chunks]

    with Pool(cpu_count()) as pool:
        pool.map(process_packet_chunk, chunk_info_list)



# Main code
if __name__ == "__main__":
    # Define the path to the PCAP file
    script_dir = os.path.dirname(os.path.abspath(__file__))
    pcap_file = os.path.join(script_dir, 'uploads', 'transmitter_uplane_dl_only_5g_nr2_1cc_400MHz_TM1p1_10ms_4pcap.pcap')
    output_dir = os.path.join(script_dir, 'output')


    # Set chunk size and max packets to meet the 30-second constraint
    process_pcap_files(pcap_file, output_dir, chunk_size=100, max_packets=1000)
