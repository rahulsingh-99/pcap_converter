from flask import Flask, render_template, request, redirect, url_for, session, flash, send_from_directory
from werkzeug.utils import secure_filename
import os
import sqlite3
import subprocess
import glob
import pandas as pd

from main import UPLOAD_FOLDER

app = Flask(__name__)
app.secret_key = 'your_secret_key'
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['OUTPUT_FOLDER'] = 'output'
app.config['ALLOWED_EXTENSIONS'] = {'pcap'}

script_dir = os.path.dirname(os.path.abspath(__file__))
output_xlsx = os.path.join(script_dir, 'output', 'output.xlsx')
final_csv = os.path.join(script_dir, 'output', 'final_output.csv')
merged_csv_path = os.path.join(script_dir, 'output', 'merged_output.csv')


def allowed_file(filename, file_types):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in file_types


# Database setup
def init_db():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT
        )
    ''')
    conn.commit()
    conn.close()

# Home Route
@app.route('/')
def home():
    return render_template('index.html')

# Signup Route
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        try:
            conn = sqlite3.connect('users.db')
            c = conn.cursor()
            c.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, password))
            conn.commit()
            flash('Signup successful! Please log in.')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Username already exists. Please choose another one.')
        finally:
            conn.close()
    return render_template('signup.html')

# Login Route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE username=? AND password=?", (username, password))
        user = c.fetchone()
        conn.close()
        if user:
            session['username'] = username
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid credentials. Please try again.')
    return render_template('login.html')

# Dashboard Route
@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    if 'username' not in session:
        return redirect(url_for('login'))

    # Flags to manage conditional rendering in the template
    pcap_uploaded = False

    if request.method == 'POST':
        # Check if a PCAP file is uploaded
        if 'file' in request.files and allowed_file(request.files['file'].filename, {'pcap'}):
            file = request.files['file']
            filename = secure_filename(file.filename)
            pcap_file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(pcap_file_path)

            # Run the output.py script for the PCAP file
            output_file = os.path.join(app.config['OUTPUT_FOLDER'], filename.rsplit('.', 1)[0] + '.xlsx')
            subprocess.run(['python', 'output.py', pcap_file_path, output_file])
            print(output_file)

            flash('PCAP file of output processed successfully.')
            pcap_uploaded = True
            return render_template('dashboard.html', username=session['username'], pcap_uploaded=pcap_uploaded)
    return render_template('dashboard.html', username=session['username'])

@app.route('/upload_csv', methods=['POST'])
def upload_file_csv():
    if 'file' not in request.files:
        flash('No file part')
        return redirect(url_for('dashboard'))
    
    file = request.files['file']
    if file.filename == '':
        flash('No selected file')
        return redirect(url_for('dashboard'))

    if file and file.filename.endswith('.pcap'):
        # Save the uploaded file
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], secure_filename(file.filename))
        file.save(filepath)
        flash('File uploaded successfully for CSV processing!')
        

        # Run the text_to_csv script for CSV processing
        output_csv_path = os.path.join(app.config['OUTPUT_FOLDER'], secure_filename(file.filename.rsplit('.', 1)[0] + '.csv'))
        subprocess.run(['python', 'text_to_csv.py', filepath, output_csv_path])

        # Redirect back to the dashboard
        return redirect(url_for('dashboard'))

    flash('Invalid file type')
    return redirect(url_for('dashboard'))


# Concatenate files
@app.route('/concatenate_files', methods=['POST'])
def concatenate_files():
    try:
        # Read the .xlsx and .csv files
        xlsx_data = pd.read_excel(output_xlsx)
        xlsx_data.reset_index(drop=True, inplace=True)

        csv_data = pd.read_csv(final_csv)
        csv_data.reset_index(drop=True, inplace=True)

        # Concatenate the data
        merged_data = pd.concat([xlsx_data, csv_data],axis = 1, ignore_index=True)

        # Save the merged data to a new CSV file
        merged_data.to_csv(merged_csv_path, index=False)
        flash('Files concatenated successfully!')

        # Redirect to the dashboard
        return redirect(url_for('dashboard'))

    except Exception as e:
        flash(f'An error occurred during concatenation: {e}')
        return redirect(url_for('dashboard'))


# Route for Uploading PCAP File
@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        flash('No file part')
        return redirect(url_for('dashboard'))

    file = request.files['file']
    if file.filename == '':
        flash('No selected file')
        return redirect(url_for('dashboard'))

    if file and file.filename.endswith('.pcap'):
        # Save the uploaded file
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], secure_filename(file.filename))
        file.save(filepath)
        flash('File uploaded successfully!')

        # Redirect back to the dashboard with file_uploaded set to True
        return render_template('dashboard.html', username=session['username'], file_uploaded=True)

    flash('Invalid file type')
    return redirect(url_for('dashboard'))



OUTPUT_DIRECTORY = os.path.join(os.getcwd(), 'output')

def clean_output_directory():
    """Delete all .txt, .xlsx, and .csv files in the output directory."""
    for extension in ["*.txt", "*.xlsx", "*.csv"]:
        files = glob.glob(os.path.join(OUTPUT_DIRECTORY, extension))
        for file in files:
            try:
                os.remove(file)
                print(f"Deleted file: {file}")
            except Exception as e:
                print(f"Error deleting file {file}: {e}")


@app.route('/download/<filename>')
def download_file(filename):
    """Serve the requested file and clean up the output directory."""
    if filename == "merged_output.csv":
        # Ensure the merged file exists
        merged_file = os.path.join(OUTPUT_DIRECTORY, filename)
        if not os.path.exists(merged_file):
            flash("Merged file does not exist. Please merge the files first.")
            return redirect(url_for('dashboard'))

        # Serve the merged file
        try:
            response = send_from_directory(OUTPUT_DIRECTORY, filename, as_attachment=True)
            
            # Clean up output directory after download
            clean_output_directory()
            return response
        except Exception as e:
            print(f"Error during file download: {e}")
            flash(f"Error during file download: {e}")
            return redirect(url_for('dashboard'))

    # Serve other files normally
    return send_from_directory(OUTPUT_DIRECTORY, filename, as_attachment=True)


# Logout Route
@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('home'))

if __name__ == '__main__':
    init_db()  # Initialize the database
    app.run(debug=False)
