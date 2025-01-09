from flask import Flask, request, redirect, url_for, session, send_file, render_template
import os
import json
import pyshark
import pandas as pd
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = 'supersecretkey'
UPLOAD_FOLDER = 'uploads'
PROCESSED_FOLDER = 'processed_files'
ALLOWED_EXTENSIONS = {'pcap', 'pcapng'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['PROCESSED_FOLDER'] = PROCESSED_FOLDER

# Ensure directories exist
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(PROCESSED_FOLDER, exist_ok=True)


# Helper function to check allowed file types
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def packet_to_dict(packet):
    """Convert packet information to a dictionary."""
    packet_info = {}

    # Frame fields
    frame_info = getattr(packet, 'frame_info', None)
    if frame_info:
        packet_info.update({
            "Frame Number": getattr(frame_info, 'number', 'N/A'),
            "Encapsulation Type": getattr(frame_info, 'encap_type', 'N/A'),
            "Arrival Time": getattr(frame_info, 'time', 'N/A'),
            "Arrival time (UTC)": getattr(frame_info, 'time_utc', 'N/A'),
            "Arrival Time (Local)": getattr(frame_info, 'time_epoch', 'N/A'),
            "Time Shift for This Packet": getattr(frame_info, 'offset_shift', 'N/A'),
            "Time delta from captured frame": getattr(frame_info, 'time_delta', 'N/A'),
            "Time delta displayed": getattr(frame_info, 'time_delta_displayed', 'N/A'),
            "Time since first frame": getattr(frame_info, 'time_relative', 'N/A'),
            "Frame Length": getattr(frame_info, 'len', 'N/A'),
            "Captured Length": getattr(frame_info, 'cap_len', 'N/A'),
            "Frame is marked": getattr(frame_info, 'marked', 'N/A'),
            "Frame is ignored": getattr(frame_info, 'ignored', 'N/A'),
            "Frame protocols": getattr(frame_info, 'protocols', 'N/A')
        })

    # Ethernet II fields
    eth_layer = getattr(packet, 'eth', None)
    if eth_layer:
        packet_info.update({
            "Ethernet Destination Address": getattr(eth_layer, 'dst_oui_resolved', '') + getattr(eth_layer, 'dst', 'N/A'),
            "Ethernet Destination LG bit": getattr(eth_layer, 'dst_lg', 'N/A'),
            "Ethernet Destination IG bit": getattr(eth_layer, 'dst_ig', 'N/A'),
            "Ethernet Source Address": getattr(eth_layer, 'src_oui_resolved', '') + getattr(eth_layer, 'src', 'N/A'),
            "Ethernet Source LG bit": getattr(eth_layer, 'src_lg', 'N/A'),
            "Ethernet Type": getattr(eth_layer, 'type', 'N/A'),
            "Ethernet Stream Index": getattr(eth_layer, 'stream', 'N/A')
        })

    # VLAN fields
    vlan_layer = getattr(packet, 'vlan', None)
    if vlan_layer:
        packet_info.update({
            "VLAN Priority": getattr(vlan_layer, 'priority', 'N/A'),
            "VLAN DEI": getattr(vlan_layer, 'dei', 'N/A'),
            "VLAN ID": getattr(vlan_layer, 'id', 'N/A'),
            "VLAN Type": getattr(vlan_layer, 'type', 'N/A'),
            "VLAN Etype": getattr(vlan_layer, 'etype', 'N/A')
        })

    # eCPRI fields
    ecpri_layer = getattr(packet, 'ecpri', None)
    if ecpri_layer:
        packet_info.update({
            "eCPRI Header": getattr(ecpri_layer, 'header', 'N/A'),
            "eCPRI Protocol Revision": getattr(ecpri_layer, 'revision', 'N/A'),
            "eCPRI Reserved Bits": getattr(ecpri_layer, 'reserved', 'N/A'),
            "eCPRI C-bit": getattr(ecpri_layer, 'cbit', 'N/A'),
            "eCPRI Length": getattr(ecpri_layer, 'length', 'N/A'),
            "eCPRI Message Type": getattr(ecpri_layer, 'type', 'N/A'),
            "eCPRI Payload Size": getattr(ecpri_layer, 'size', 'N/A'),
            "eCPRI Payload": getattr(ecpri_layer, 'payload', 'N/A')
        })

    # O-RAN Fronthaul CUS fields
    oran_layer = getattr(packet, 'oran_fh_cus', None)
    if oran_layer:
        oran_info = {
            "DU Port ID": getattr(oran_layer, 'du_port_id', 'N/A'),
            "BandSector ID": getattr(oran_layer, 'bandsector_id', 'N/A'),
            "CC ID": getattr(oran_layer, 'cc_id', 'N/A'),
            "RU Port ID": getattr(oran_layer, 'ru_port_id', 'N/A'),
            "c_eAxC_ID": getattr(oran_layer, 'c_eaxc_id', 'N/A'),
            "Sequence ID": getattr(oran_layer, 'sequence_id', 'N/A'),
            "E-Bit": getattr(oran_layer, 'e_bit', 'N/A'),
            "Subsequence ID": getattr(oran_layer, 'subsequence_id', 'N/A'),
            "Data Direction": getattr(oran_layer, 'data_direction', 'N/A'),
            "Payload Version": getattr(oran_layer, 'payloadversion', 'N/A'),
            "Filter Index": getattr(oran_layer, 'filterindex', 'N/A'),
            "Frame ID": getattr(oran_layer, 'frameid', 'N/A'),
            "Subframe ID": getattr(oran_layer, 'subframe_id', 'N/A'),
            "Slot ID": getattr(oran_layer, 'slotid', 'N/A'),
            "Start Symbol": getattr(oran_layer, 'startsymbolid', 'N/A'),
            "Symbol Identifier": getattr(oran_layer, 'symbolid', 'N/A'),
            "refA": getattr(oran_layer, 'refa', 'N/A'),
            "Number Of Sections": getattr(oran_layer, 'numberofsections', 'N/A'),
            "Section Type": getattr(oran_layer, 'sectiontype', 'N/A'),
            "Section ID": getattr(oran_layer, 'sectionid', 'N/A'),
            "rb": getattr(oran_layer, 'rb', 'N/A'),
            "SymInc": getattr(oran_layer, 'syminc', 'N/A'),
            "Start Prbu": getattr(oran_layer, 'startprbu', 'N/A'),
            "Num Prbu": getattr(oran_layer, 'numprbu', 'N/A'),
            "User Data IQ width": getattr(oran_layer, 'udcomphdrwidth', 'N/A'),
            "User Data Compression Method": getattr(oran_layer, 'udcomphdrmeth', 'N/A'),
            "Reserved8": getattr(oran_layer, 'reserved8', 'N/A'),
            "Prb": getattr(oran_layer, 'prb', 'N/A'),
            "RE Mask": getattr(oran_layer, 'remask', 'N/A'),
            "Number of Symbols": getattr(oran_layer, 'numsymbol', 'N/A'),
            "Extension Flag": getattr(oran_layer, 'ef', 'N/A'),
            "Beam ID": getattr(oran_layer, 'beamid', 'N/A'),
            "UdCompparam": getattr(oran_layer, 'udcompparam', 'N/A'),
            "Reserved_Bits": getattr(oran_layer, 'reserved8', 'N/A'),
            "Reserved Bits": getattr(oran_layer, 'reserved', 'N/A'),
            "Exponent": getattr(oran_layer, 'exponent', 'N/A'),
            "IQ User Data": getattr(oran_layer, 'iq_user_data', 'N/A'),
            "I sample": getattr(oran_layer, 'isample', 'N/A'),
            "Q sample": getattr(oran_layer, 'qsample', 'N/A')
        }
        packet_info.update(oran_info)

    # Malformed fields
    malformed_layer = getattr(packet, '_ws.malformed', None)
    if malformed_layer:
        packet_info.update({
            "_ws_expert": getattr(malformed_layer, '_ws_expert', 'N/A'),
            "_ws_expert_message": getattr(malformed_layer, '_ws_expert_message', 'N/A'),
            "_ws_expert_severity": getattr(malformed_layer, '_ws_expert_severity', 'N/A'),
            "_ws_expert_group": getattr(malformed_layer, '_ws_expert_group', 'N/A'),
            "Raw Mode": getattr(malformed_layer, 'raw_mode', 'N/A')
        })

    return packet_info

# Helper function to save users
def save_users(users):
    with open('users.json', 'w') as f:
        json.dump(users, f)


# Helper function to load users
def load_users():
    if os.path.exists('users.json'):
        with open('users.json', 'r') as f:
            return json.load(f)
    return {}

@app.route('/')
def index():
    return render_template('index.html')


# Sign-up route
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        users = load_users()
        if username in users:
            return 'Username already exists! Try logging in.'

        users[username] = password
        save_users(users)
        return redirect(url_for('login'))
    return render_template('signup.html')


# Login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        users = load_users()
        if username in users and users[username] == password:
            session['username'] = username
            return redirect(url_for('upload_file'))
        return 'Invalid credentials! Try again.'
    return render_template('login.html')


# Upload file route
@app.route('/upload', methods=['GET', 'POST'])
def upload_file():
    if 'username' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        if 'file' not in request.files:
            return 'No file part'
        file = request.files['file']
        if file.filename == '':
            return 'No selected file'
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)
            return redirect(url_for('process_file', filename=filename))

    return render_template('upload.html')


import asyncio
import logging

logging.basicConfig(level=logging.DEBUG)
@app.route('/process/<filename>', methods=['GET'])
async def process_file(filename):
    if 'username' not in session:
        return redirect(url_for('login'))

    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    output_file = os.path.join(app.config['PROCESSED_FOLDER'], f"{filename}.xlsx")

    try:
        # Process the PCAP file and save the output as Excel
        capture = await asyncio.to_thread(pyshark.FileCapture, file_path)  # Running in a thread to avoid blocking
        packets_data = []

        for packet in capture:
            try:
                packet_info = await asyncio.to_thread(packet_to_dict, packet)
                packets_data.append(packet_info)
            except Exception as e:
                print(f"Error processing packet: {e}")

        df = pd.DataFrame(packets_data)
        df.to_excel(output_file, index=False, engine='openpyxl')
        return send_file(output_file, as_attachment=True)

    except Exception as e:
        return f"An error occurred while processing the file: {e}"

if __name__ == '__main__':
    app.run(debug=True,threaded=True)
