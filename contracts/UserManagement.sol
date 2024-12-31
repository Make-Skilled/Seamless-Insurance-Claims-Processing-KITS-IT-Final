// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract UserManagement {
    // Struct to store user information
    struct User {
        string role; // Role of the user (user, hospital, police)
        string addressDetails; // Address of the user
        string username; // Username
        string email; // Email
        bytes32 passwordHash; // Hashed password for security
    }

    // Mapping to store users by their Ethereum address
    mapping(address => User) private users;

    // Event for user registration
    event UserRegistered(address indexed userAddress, string username, string role);

    // Function to register a new user
    function registerUser(
        string memory _role,
        string memory _addressDetails,
        string memory _username,
        string memory _email,
        string memory _password
    ) public {
        require(bytes(users[msg.sender].username).length == 0, "User already registered.");
        require(bytes(_role).length > 0, "Role is required.");
        require(bytes(_addressDetails).length > 0, "Address is required.");
        require(bytes(_username).length > 0, "Username is required.");
        require(bytes(_email).length > 0, "Email is required.");
        require(bytes(_password).length >= 6, "Password must be at least 6 characters.");

        // Store user data
        users[msg.sender] = User({
            role: _role,
            addressDetails: _addressDetails,
            username: _username,
            email: _email,
            passwordHash: keccak256(abi.encodePacked(_password)) // Hash the password
        });

        emit UserRegistered(msg.sender, _username, _role);
    }

    // Function to login a user
    function loginUser(string memory username, string memory password) public view returns (bool) {
    require(bytes(users[msg.sender].username).length > 0, "User not registered.");
    require(
        keccak256(abi.encodePacked(password)) == users[msg.sender].passwordHash,
        "Invalid credentials."
    );
    return true; // Login successful
}

    // Function to retrieve user details
    function getUserDetails() public view returns (string memory role, string memory addressDetails, string memory username, string memory email) {
        require(bytes(users[msg.sender].username).length > 0, "User not registered.");
        User memory user = users[msg.sender];
        return (user.role, user.addressDetails, user.username, user.email);
    }
}
