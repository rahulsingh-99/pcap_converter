import pyshark 
import csv    

def extract_iq_samples(pcap_file, output_csv):
    iq_samples = []
    
    cap = pyshark.FileCapture(pcap_file, only_summaries=False)
    
    for packet in cap:
        try:
            if hasattr(packet, 'data'):
                data_bytes = packet.data.data.split(':')
                
                for i in range(0, len(data_bytes), 2):
                    if i + 1 < len(data_bytes):

                        i_sample = int(data_bytes[i], 16)
                        q_sample = int(data_bytes[i+1], 16)
                        
                        iq_samples.append([i_sample, q_sample])
        except Exception as e:
            print(f"Error processing packet: {e}")
    
    cap.close()
    
    with open(output_csv, 'w', newline='') as csvfile:
        csvwriter = csv.writer(csvfile)
        
        csvwriter.writerow(['I_Sample', 'Q_Sample'])
        
        csvwriter.writerows(iq_samples)
    
    print(f"Extracted {len(iq_samples)} I/Q samples to {output_csv}")

# Example usage
if __name__ == "__main__":

    input_pcap = r"C:\Users\Rahul Singh\Documents\pacap_project\transmitter_uplane_dl_only_5g_nr2_1cc_400MHz_TM1p1_10ms_4pcap.pcap"
    output_csv = r"C:\Users\Rahul Singh\Documents\pacap_project\output\samples.csv"
    
    extract_iq_samples(input_pcap, output_csv)