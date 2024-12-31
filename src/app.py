from flask import Flask, render_template, request, redirect, url_for, flash, session,jsonify
from web3 import Web3, HTTPProvider
import json
import bcrypt
from werkzeug.utils import secure_filename
import os
import hashlib

app = Flask(__name__)
app.secret_key = '1234'

# Configuration
STATIC_FOLDER = 'static'
UPLOAD_FOLDER = os.path.join(STATIC_FOLDER, 'uploads')
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
 
# Ensure the uploads directory exists
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

def connect_with_register_blockchain(acc):
    blockchainServer='http://127.0.0.1:7545'

    web3=Web3(HTTPProvider(blockchainServer))
    web3.eth.defaultAccount=acc

    artifact_path='../build/contracts/UserManagement.json'
    with open(artifact_path) as f:
        contract_json=json.load(f)
        contract_abi=contract_json['abi']
        contract_address=contract_json['networks']['5777']['address']
    contract=web3.eth.contract(address=contract_address,abi=contract_abi)
    return(contract,web3)

def connect_with_insurance(acc):
    blockchainServer='http://127.0.0.1:7545'

    web3=Web3(HTTPProvider(blockchainServer))
    web3.eth.defaultAccount=acc

    artifact_path='../build/contracts/LifeInsurance.json'
    with open(artifact_path) as f:
        contract_json=json.load(f)
        contract_abi=contract_json['abi']
        contract_address=contract_json['networks']['5777']['address']
    contract=web3.eth.contract(address=contract_address,abi=contract_abi)
    return(contract,web3)
 
@app.route('/')
def main():
    return render_template('index.html')
 
@app.route('/login')
def login():
    return render_template('login.html')
 
@app.route('/signup')
def signup():
    return render_template('signup.html')

@app.route('/home')
def home():
    return render_template('home.html')

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/contact')
def contact():
    return render_template('contact.html')

@app.route('/error')
def error():
    return render_template('404.html')

@app.route('/feature')
def feature():
    return render_template('feature.html')

@app.route('/appointment')
def appointment():
    return render_template('appointment.html')

@app.route('/Bussiness')
def Bussiness():
    return render_template('Bussiness.html')

@app.route('/LifeInsurance')
def LifeInsurance():
    user = session.get('user')
    if not user:
        return redirect(url_for('login'))
    return render_template('LifeInsurance.html')
 
@app.route('/register', methods=['POST'])
def register_user():
    try:
        # Parse form data
        role = request.form.get('role')
        email = request.form.get('email').lower()
        password = request.form.get('password')
        username = request.form.get('username')
        address = request.form.get('address')  # Retrieve Ethereum address from the form

        # Connect to the blockchain
        contract, web3 = connect_with_register_blockchain(address)
        if not contract or not web3:
            raise Exception("Failed to connect to blockchain.")
        
        # Input validation
        if not address or not email or not password or not username or not role:
            return render_template('signup.html', error="All fields are required"), 400

        # Hash the password
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

        # Interact with the blockchain to add the user
        try:
            tx_hash = contract.functions.registerUser(role, email, hashed_password, username, address).transact()
            web3.eth.wait_for_transaction_receipt(tx_hash)
        except Exception:
            import traceback
            print(f"Blockchain error during registration: {traceback.format_exc()}")
            return render_template('signup.html', error="Blockchain interaction failed. Please try again later."), 500

        # If successful, return a success message
        return render_template('signup.html', message="Registration successful! You can now log in."), 201

    except Exception as e:
        import traceback
        print(f"Error during registration: {traceback.format_exc()}")
        return render_template('signup.html', error="An internal error occurred. Please try again later."), 500

@app.route('/login', methods=['POST'])
def login_user():
    try:
        # Parse form data
        role = request.form.get('role')
        username = request.form.get('username')
        password = request.form.get('password')
        user_address = request.form.get('address')  # Ethereum address provided by the user

        # Input validation
        if not username or not password or not user_address:
            return render_template('login.html', error="All fields are required"), 400

        # Connect to the blockchain
        contract, web3 = connect_with_register_blockchain(user_address)
        if not contract or not web3:
            return render_template('login.html', error="Failed to connect to blockchain"), 500

        # Fetch user data from the blockchain
        try:
            user_data = contract.functions.getUserDetails().call()  # Assumes a `getUser` function exists
        except Exception as blockchain_error:
            print(f"Blockchain error during user data retrieval: {blockchain_error}")
            return render_template('login.html', error="Blockchain interaction failed"), 500

        if not user_data:
            return render_template('login.html', error="User not found"), 404

        stored_hashed_password = user_data[2]  # Assuming password is stored at index 2 in the `getUser` return data

        # Verify the password
        if not bcrypt.checkpw(password.encode('utf-8'), stored_hashed_password.encode('utf-8')):
            return render_template('login.html', error="Invalid username or password"), 401

        # Save user session securely
        session['username']=username
        session['user'] = {
            'address': user_address,
            'role': role,
            'username': username,
        }

        # Redirect to the home page
        return render_template('index.html', user=session['user']), 200

    except Exception as e:
        print(f"Error during login: {e}")
        return render_template('login.html', error="An internal error occurred"), 500
    
@app.route('/upload/user-details', methods=['POST'])
def upload_user_details():
    user = session.get('user')
    if not user:
        return render_template('login.html', error="Please log in first.")

    try:
        contract, web3 = connect_with_insurance(user['address'])

        # Get form data
        username = str(request.form.get('username'))
        policy_id = str(request.form.get('policy_id'))
        aadhaar_number = int(request.form.get('aadhaar_number'))
        phone_number = str(request.form.get('phone_number'))

        if not username or not policy_id or not aadhaar_number or not phone_number:
            return render_template('home.html', error="All fields are required.")

        # Store details on blockchain
        tx_hash = contract.functions.submitUserDetails(username, policy_id, aadhaar_number, phone_number).transact()
        web3.eth.wait_for_transaction_receipt(tx_hash)

        flash("User details uploaded successfully.", "success")
        return render_template('home.html', user=user)
    except Exception as e:
        print(f"Error uploading user details: {e}")
        flash("An error occurred while uploading user details. Please try again.", "error")
        return render_template('home.html', user=user, error="An error occurred.")

@app.route('/upload/nominee-details', methods=['POST'])
def upload_nominee_details():
    user = session.get('user')
    if not user:
        return render_template('login.html', error="Please log in first.")

    try:
        contract, web3 = connect_with_insurance(user['address'])

        # Get form data
        nominee_name = str(request.form.get('nominee_name'))
        nominee_aadhaar = int(request.form.get('nominee_aadhaar'))
        nominee_phone = str(request.form.get('nominee_phone'))

        if not nominee_name or not nominee_aadhaar or not nominee_phone:
            return render_template('home.html', error="All fields are required.")

        # Store details on blockchain
        tx_hash = contract.functions.submitNomineeDetails(nominee_name, nominee_aadhaar, nominee_phone).transact()
        web3.eth.wait_for_transaction_receipt(tx_hash)

        flash("Nominee details uploaded successfully.", "success")
        return render_template('home.html', user=user)
    except Exception as e:
        print(f"Error uploading nominee details: {e}")
        flash("An error occurred while uploading nominee details. Please try again.", "error")
        return render_template('home.html', user=user, error="An error occurred.")

@app.route('/upload/bank-details', methods=['POST'])
def upload_bank_details():
    user = session.get('user')
    if not user:
        return render_template('login.html', error="Please log in first.")

    try:
        contract, web3 = connect_with_insurance(user['address'])

        # Get form data
        bank_name = request.form.get('bank_name')
        account_number = request.form.get('account_number')
        ifsc_code = request.form.get('ifsc_code')

        if not bank_name or not account_number or not ifsc_code:
            return render_template('home.html', error="All fields are required.")

        # Store details on blockchain
        tx_hash = contract.functions.submitBankDetails(bank_name, account_number, ifsc_code).transact()
        web3.eth.wait_for_transaction_receipt(tx_hash)

        flash("Bank details uploaded successfully.", "success")
        return render_template('home.html', user=user)
    except Exception as e:
        print(f"Error uploading bank details: {e}")
        flash("An error occurred while uploading bank details. Please try again.", "error")
        return render_template('home.html', user=user, error="An error occurred.")

@app.route('/upload/certificate-upload', methods=['POST'])
def upload_certificate():
    try:
        # Check user session
        user = session.get('user')
        if not user:
            return render_template('login.html', error="Please log in first.")

        # Check for uploaded files
        if 'policy_photo' not in request.files or 'reports' not in request.files:
            return render_template('upload-certificate.html', message="Both 'policy_photo' and 'reports' are required."), 400

        # Get the files
        policy_photo = request.files['policy_photo']
        reports = request.files['reports']

        # Check if the files have names
        if policy_photo.filename == '' or reports.filename == '':
            return render_template('upload-certificate.html', message="No file selected for one or more fields."), 400

        # Secure and save files
        policy_photo_filename = secure_filename(policy_photo.filename)
        reports_filename = secure_filename(reports.filename)

        policy_photo_path = os.path.join(app.config['UPLOAD_FOLDER'], policy_photo_filename)
        reports_path = os.path.join(app.config['UPLOAD_FOLDER'], reports_filename)

        # Save files locally or to the specified directory
        policy_photo.save(policy_photo_path)
        reports.save(reports_path)

        # Generate hashes for the files
        policy_photo.seek(0)  # Reset the file pointer
        reports.seek(0)       # Reset the file pointer
        policy_photo_hash = hashlib.sha256(policy_photo.read()).hexdigest()
        reports_hash = hashlib.sha256(reports.read()).hexdigest()

        print(f"Policy photo hash: {policy_photo_hash}")
        print(f"Reports hash: {reports_hash}")

        # Connect to the blockchain
        contract, web3 = connect_with_insurance(user['address'])
        if not contract or not web3:
            raise Exception("Failed to connect to blockchain.")

        # Store certificate details on the blockchain
        try:
            tx_hash = contract.functions.submitCertificateDetails(
                policy_photo_hash, reports_hash).transact()
            web3.eth.wait_for_transaction_receipt(tx_hash)
            print(f"Transaction successful: {tx_hash.hex()}")
        except Exception as blockchain_error:
            print(f"Blockchain interaction error: {blockchain_error}")
            return render_template('LifeInsurance.html', message="Failed to record certificate on blockchain."), 500

        # Return success message
        return render_template('LifeInsurance.html', message="Certificate uploaded and recorded successfully."), 200

    except Exception as e:
        import traceback
        print(f"Error during upload: {traceback.format_exc()}")
        return jsonify({'error': f'An error occurred: {str(e)}'}), 500

@app.route('/logout')
def logout():
    session.clear()
    return render_template('index.html')

if __name__ == '__main__':
    app.run(debug=True, port=9001)