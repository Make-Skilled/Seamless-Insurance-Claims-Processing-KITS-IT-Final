from flask import Flask, render_template, request, redirect, url_for, flash, session
from web3 import Web3, HTTPProvider
import json

app = Flask(__name__)
app.secret_key = '1234'

# Blockchain Configuration
web3 = Web3(HTTPProvider('http://127.0.0.1:7545'))  # Ganache local blockchain
web3.eth.defaultAccount = web3.eth.accounts[0]

artifact_path = "./build/contracts/RoleBasedAuth.json"  # Path to the compiled contract JSON
with open(artifact_path) as f:
    contract_artifact = json.load(f) 
    contract_abi = contract_artifact['abi']
    contract_address = contract_artifact['networks']['5777']['address']

contract = web3.eth.contract(address=contract_address, abi=contract_abi)

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/login')
def log():
    return render_template('login.html')

@app.route('/signup')
def sign():
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        address = request.form['address']
        try:
            username, role = contract.functions.loginUser(address).call()
            session['username'] = username
            session['role'] = role
            flash(f'Welcome {username}! Role: {role}')
            return redirect(url_for('home'))
        except Exception as e:
            flash('Login failed. Please check your address or contact admin.')
            print(e)

    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if 'role' not in session or session['role'] != 'admin':
        flash('Only admin can register new users.')
        return redirect(url_for('login'))

    if request.method == 'POST':
        address = request.form['address']
        username = request.form['username']
        email = request.form['email']
        role = request.form['role']
        try:
            tx_hash = contract.functions.registerUser(address, username, email, role).transact()
            web3.eth.waitForTransactionReceipt(tx_hash)
            flash(f'User {username} with role {role} registered successfully.')
            return redirect(url_for('home'))
        except Exception as e:
            flash('Registration failed. Please check the details and try again.')
            print(e)

    return render_template('register.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully.')
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
