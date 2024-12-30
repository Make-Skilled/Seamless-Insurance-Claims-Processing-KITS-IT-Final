// SPDX-License-Identifier: MIT
pragma solidity 0.8.19;

contract RoleBasedAuth {
    struct User {
        string username;
        string email;
        string role;
        bool exists;
    }

    mapping(address => User) public users;
    address public admin;

    constructor() {
        admin = msg.sender;
    }

    modifier onlyAdmin() {
        require(msg.sender == admin, "Only admin can perform this action");
        _;
    }

    function registerUser(
        address _userAddress,
        string memory _username,
        string memory _email,
        string memory _role
    ) public onlyAdmin returns (bool) {
        require(!users[_userAddress].exists, "User already exists");
        users[_userAddress] = User(_username, _email, _role, true);
        return true;
    }

    function loginUser(address _userAddress) public view returns (string memory, string memory) {
        require(users[_userAddress].exists, "User does not exist");
        return (users[_userAddress].username, users[_userAddress].role);
    }

    function getUserRole(address _userAddress) public view returns (string memory) {
        require(users[_userAddress].exists, "User does not exist");
        return users[_userAddress].role;
    }

    function updateUser(
        address _userAddress,
        string memory _username,
        string memory _email,
        string memory _role
    ) public onlyAdmin returns (bool) {
        require(users[_userAddress].exists, "User does not exist");
        users[_userAddress] = User(_username, _email, _role, true);
        return true;
    }
}
