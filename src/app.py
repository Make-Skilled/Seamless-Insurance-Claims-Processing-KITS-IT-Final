from flask import Flask, render_template, request, redirect, url_for, flash, session,jsonify
from web3 import Web3, HTTPProvider
import json
import bcrypt
from werkzeug.utils import secure_filename
import os
import hashlib

adminUsername = "admin"
adminPasswordHash = bcrypt.hashpw("admin_password".encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
adminAddress = "0xf7A255f945c3e9E2e558328aE4950B6432Af5574"  # Replace with the actual admin Ethereum address

app = Flask(__name__)
app.secret_key = '1234'

# Configuration
app.config['UPLOAD_FOLDER'] = 'static/uploads'

# Ensure base upload folder exists
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

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

@app.route('/service')
def service():
    return render_template('service.html')

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

        if role == "admin":
            if user_address != adminAddress:
                return render_template('login.html', error="Invalid admin address"), 401

            if username != adminUsername:
                return render_template('login.html', error="Invalid admin username"), 401

            if not bcrypt.checkpw(password.encode('utf-8'), adminPasswordHash.encode('utf-8')):
                return render_template('login.html', error="Invalid admin password"), 401

            # Save admin session
            session['username'] = username
            session['user'] = {
                'address': user_address,
                'role': role,
                'username': username,
            }
            return render_template('adminhome.html', user=session['user'])

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

        if role == "hospital":
            return render_template('hospital_dashboard.html', user=session['user'])
        elif role == "police":
            return render_template('police_dashboard.html', user=session['user'])
        else:
            return render_template('LifeInsurance.html', user=session['user'])

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
        insurance_type=str(request.form.get('insurance_type'))
        username = str(request.form.get('username'))
        policy_id = str(request.form.get('policy_id'))
        aadhaar_number = int(request.form.get('aadhaar_number'))
        phone_number = str(request.form.get('phone_number'))

        if not username or not policy_id or not aadhaar_number or not phone_number or not insurance_type:
            return render_template('LifeInsurance.html', error="All fields are required.")

        # Store details on blockchain
        tx_hash = contract.functions.submitUserDetails(insurance_type, username, policy_id, aadhaar_number, phone_number).transact()
        web3.eth.wait_for_transaction_receipt(tx_hash)

        flash("User details uploaded successfully.", "success")
        return render_template('LifeInsurance.html', user=user)
    except Exception as e:
        print(f"Error uploading user details: {e}")
        flash("An error occurred while uploading user details. Please try again.", "error")
        return render_template('LifeInsurance.html', user=user, error="An error occurred.")

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
            return render_template('LifeInsurance.html', error="All fields are required.")

        # Store details on blockchain
        tx_hash = contract.functions.submitNomineeDetails(nominee_name, nominee_aadhaar, nominee_phone).transact()
        web3.eth.wait_for_transaction_receipt(tx_hash)

        flash("Nominee details uploaded successfully.", "success")
        return render_template('LifeInsurance.html', user=user)
    except Exception as e:
        print(f"Error uploading nominee details: {e}")
        flash("An error occurred while uploading nominee details. Please try again.", "error")
        return render_template('LifeInsurance.html', user=user, error="An error occurred.")

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
        return render_template('LifeInsurance.html', user=user)
    except Exception as e:
        print(f"Error uploading bank details: {e}")
        flash("An error occurred while uploading bank details. Please try again.", "error")
        return render_template('LifeInsurance.html', user=user, error="An error occurred.")

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

        # Create subdirectory path dynamically
        user_folder = os.path.join(app.config['UPLOAD_FOLDER'], user['role'])
        if not os.path.exists(user_folder):
            os.makedirs(user_folder)  # Create folder if it doesn't exist

        # Secure and save files
        policy_photo_filename = secure_filename(policy_photo.filename)
        reports_filename = secure_filename(reports.filename)

        policy_photo_path = os.path.join(user_folder, policy_photo_filename)
        reports_path = os.path.join(user_folder, reports_filename)

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
    

@app.route('/upload/hospital-details', methods=['POST'])
def upload_hospital_details():
    user = session.get('user')
    if not user or user['role'] != 'hospital':
        return render_template('login.html', error="Please log in as a hospital first.")

    try:
        # Check for the required form fields
        policy_id = request.form.get('policy_id')
        full_name = request.form.get('full_name')
        contact_info = request.form.get('contact_info')
        user_photo = request.files.get('user_photo')

        if not policy_id or not full_name or not contact_info or not user_photo:
            return render_template('hospital_dashboard.html', error="All fields are required."), 400

        # Secure and save the uploaded photo in the 'hospital' folder inside the UPLOAD_FOLDER
        hospital_folder = os.path.join(app.config['UPLOAD_FOLDER'], user['role'])
        
        # Create the 'hospital' folder if it doesn't exist
        if not os.path.exists(hospital_folder):
            os.makedirs(hospital_folder)
        
        filename = secure_filename(user_photo.filename)
        user_photo_path = os.path.join(hospital_folder, filename)  # Save inside 'hospital' folder
        user_photo.save(user_photo_path)

        # Assuming we want to hash the photo for verification later
        user_photo.seek(0)  # Reset the file pointer
        user_photo_hash = hashlib.sha256(user_photo.read()).hexdigest()
        
        # Connect to the blockchain to store the details
        contract, web3 = connect_with_insurance(user['address'])
        if not contract or not web3:
            return render_template('hospital_dashboard.html', error="Failed to connect to blockchain.")

        # Store details on blockchain (you might need to implement a contract function to handle this)
        try:
            tx_hash = contract.functions.submitHospitalDetails(policy_id, full_name, contact_info, user_photo_hash).transact()
            web3.eth.wait_for_transaction_receipt(tx_hash)
            flash("Hospital details uploaded successfully.", "success")
            return render_template('hospital_dashboard.html', user=user)

        except Exception as blockchain_error:
            print(f"Blockchain error during hospital details upload: {blockchain_error}")
            return render_template('hospital_dashboard.html', error="Failed to upload hospital details to blockchain."), 500

    except Exception as e:
        print(f"Error during hospital details upload: {e}")
        flash("An error occurred while uploading hospital details. Please try again.", "error")
        return render_template('hospital_dashboard.html', error="An error occurred.")

@app.route('/upload/police-details', methods=['POST'])
def upload_police_details():
    user = session.get('user')
    if not user or user['role'] != 'police':
        return render_template('login.html', error="Please log in as a police first.")

    try:
        # Check for the required form fields
        policy_id = request.form.get('policy_id')
        full_name = request.form.get('full_name')
        contact_info = request.form.get('contact_info')
        user_photo = request.files.get('user_photo')

        if not policy_id or not full_name or not contact_info or not user_photo:
            return render_template('police_dashboard.html', error="All fields are required."), 400

        # Secure and save the uploaded photo in the 'hospital' folder inside the UPLOAD_FOLDER
        police_folder = os.path.join(app.config['UPLOAD_FOLDER'], user['role'])
        # Create the 'hospital' folder if it doesn't exist
        if not os.path.exists(police_folder):
            os.makedirs(police_folder)
        
        filename = secure_filename(user_photo.filename)
        user_photo_path = os.path.join(police_folder, filename)  # Save inside 'hospital' folder
        user_photo.save(user_photo_path)

        # Assuming we want to hash the photo for verification later
        user_photo.seek(0)  # Reset the file pointer
        user_photo_hash = hashlib.sha256(user_photo.read()).hexdigest()
        
        # Connect to the blockchain to store the details
        contract, web3 = connect_with_insurance(user['address'])
        if not contract or not web3:
            return render_template('police_dashboard.html', error="Failed to connect to blockchain.")

        # Store details on blockchain (you might need to implement a contract function to handle this)
        try:
            tx_hash = contract.functions.submitPoliceDetails(policy_id, full_name, contact_info, user_photo_hash).transact()
            web3.eth.wait_for_transaction_receipt(tx_hash)
            flash("Hospital details uploaded successfully.", "success")
            return render_template('police_dashboard.html', user=user)

        except Exception as blockchain_error:
            print(f"Blockchain error during hospital details upload: {blockchain_error}")
            return render_template('police_dashboard.html', error="Failed to upload hospital details to blockchain."), 500

    except Exception as e:
        print(f"Error during hospital details upload: {e}")
        flash("An error occurred while uploading hospital details. Please try again.", "error")
        return render_template('police_dashboard.html', error="An error occurred.")


@app.route('/admin-home', methods=['GET'])
def admin_home():
    try:
        # Check if the logged-in user is an admin
        user = session.get('user')
        if not user or user['role'] != 'admin':
            return redirect(url_for('login'))

        # Connect to the blockchain
        contract, web3 = connect_with_insurance(adminAddress)
        if not contract or not web3:
            return render_template('adminhome.html', error="Failed to connect to blockchain")

        # Fetch all users' details
        try:
            all_users = contract.functions.getAllUsers().call()
        except Exception as blockchain_error:
            print(f"Blockchain error during all users' data retrieval: {blockchain_error}")
            return render_template('adminhome.html', error="Failed to fetch user list from blockchain")

        # Prepare user list for rendering
        user_data = []
        index=0
        for user in all_users:
            user_data.append({
                'index': index,
                'policy_type': user[0][0],
                'username': user[0][1],
                'policyId': user[0][2],
                'aadhaarNumber': user[0][3],
                'phoneNumber': user[0][4],
            })
            index+=1

        return render_template('adminhome.html', users=user_data)

    except Exception as e:
        print(f"Error in admin home: {e}")
        return render_template('adminhome.html', error="An internal error occurred")


@app.route('/admin-dashboard/<int:index>', methods=['GET'])
def admin_dashboard(index):
    try:
        # Check if the logged-in user is an admin
        user = session.get('user')
        if not user or user['role'] != 'admin':
            return redirect(url_for('login'))

        # Connect to the blockchain
        contract, web3 = connect_with_insurance(adminAddress)
        if not contract or not web3:
            return render_template('admindashboard.html', error="Failed to connect to blockchain")

        # Fetch user details by index
        try:
            all_users = contract.functions.getAllUsers().call()
            if index < 0 or index >= len(all_users):
                return render_template('admindashboard.html', error="Invalid user index")

            user_details = all_users[index]
        except Exception as blockchain_error:
            print(f"Blockchain error during user details retrieval: {blockchain_error}")
            return render_template('admindashboard.html', error="Failed to fetch user details from blockchain")

        # Prepare detailed user data for rendering
        print(all_users)
        user_data = {
            'policy_type': user_details[0][0],
            'username': user_details[0][1],
            'policyId': user_details[0][2],
            'aadhaarNumber': user_details[0][3],
            'phoneNumber': user_details[0][4],
            'nominee_name':user_details[1][0],
            'nominee_aadhaar':user_details[1][1],
            'nominee_phone':user_details[1][2],
            'bank_name':user_details[2][0],
            'bank_number':user_details[2][1],
            'bank_ifsc':user_details[2][2],
            # Add other fields as needed
        }
        return render_template('admindashboard.html', user=user_data)

    except Exception as e:
        print(f"Error in admin dashboard: {e}")
        return render_template('admindashboard.html', error="An internal error occurred")


@app.route('/logout')
def logout():
    session.clear()
    return render_template('index.html')

if __name__ == '__main__':
    app.run(debug=True, port=9001)