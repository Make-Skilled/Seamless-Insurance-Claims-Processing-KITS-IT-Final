from flask import Flask, render_template, request, redirect, url_for, flash, session
from web3 import Web3, HTTPProvider
import json
import bcrypt

app = Flask(__name__)
app.secret_key = '1234'

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
        session['user'] = {
            'address': user_address,
            'role': role,
            'username': username,
        }

        # Redirect to the home page
        return render_template('home.html', user=session['user']), 200

    except Exception as e:
        print(f"Error during login: {e}")
        return render_template('login.html', error="An internal error occurred"), 500

if __name__ == '__main__':
    app.run(debug=True, port=9001)