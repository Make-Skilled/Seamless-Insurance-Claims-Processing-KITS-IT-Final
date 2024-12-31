// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract LifeInsurance {

    struct UserDetails {
        string username;
        string policyId;
        uint256 aadhaarNumber;
        string phoneNumber;
    }

    struct NomineeDetails {
        string nomineeName;
        uint256 nomineeAadhaar;
        string nomineePhone;
    }

    struct BankDetails {
        string bankName;
        string accountNumber;
        string ifscCode;
    }

    struct CertificateDetails {
        string policyPhotoHash; // Use hash of the file for storage efficiency
        string reportsHash;
    }

    struct InsuranceRecord {
        UserDetails userDetails;
        NomineeDetails nomineeDetails;
        BankDetails bankDetails;
        CertificateDetails certificateDetails;
    }

    mapping(address => InsuranceRecord) private insuranceRecords;

    event DetailsSubmitted(
        address indexed userAddress,
        string category, // "User", "Nominee", "Bank", "Certificate"
        string description
    );

    modifier onlyUser(address userAddress) {
        require(userAddress == msg.sender, "Unauthorized: You can only update your own records.");
        _;
    }

    // Function to store user details
    function submitUserDetails(
        string memory _username,
        string memory _policyId,
        uint256 _aadhaarNumber,
        string memory _phoneNumber
    ) public {
        insuranceRecords[msg.sender].userDetails = UserDetails(_username, _policyId, _aadhaarNumber, _phoneNumber);
        emit DetailsSubmitted(msg.sender, "User", "User details updated successfully.");
    }

    // Function to store nominee details
    function submitNomineeDetails(
        string memory _nomineeName,
        uint256 _nomineeAadhaar,
        string memory _nomineePhone
    ) public {
        insuranceRecords[msg.sender].nomineeDetails = NomineeDetails(_nomineeName, _nomineeAadhaar, _nomineePhone);
        emit DetailsSubmitted(msg.sender, "Nominee", "Nominee details updated successfully.");
    }

    // Function to store bank details
    function submitBankDetails(
        string memory _bankName,
        string memory _accountNumber,
        string memory _ifscCode
    ) public {
        insuranceRecords[msg.sender].bankDetails = BankDetails(_bankName, _accountNumber, _ifscCode);
        emit DetailsSubmitted(msg.sender, "Bank", "Bank details updated successfully.");
    }

    // Function to store certificate details (hashes for efficiency)
    function submitCertificateDetails(
        string memory _policyPhotoHash,
        string memory _reportsHash
    ) public {
        insuranceRecords[msg.sender].certificateDetails = CertificateDetails(_policyPhotoHash, _reportsHash);
        emit DetailsSubmitted(msg.sender, "Certificate", "Certificate details updated successfully.");
    }

    // Function to retrieve user details
    function getUserDetails(address userAddress)
        public
        view
        onlyUser(userAddress)
        returns (UserDetails memory)
    {
        return insuranceRecords[userAddress].userDetails;
    }

    // Function to retrieve nominee details
    function getNomineeDetails(address userAddress)
        public
        view
        onlyUser(userAddress)
        returns (NomineeDetails memory)
    {
        return insuranceRecords[userAddress].nomineeDetails;
    }

    // Function to retrieve bank details
    function getBankDetails(address userAddress)
        public
        view
        onlyUser(userAddress)
        returns (BankDetails memory)
    {
        return insuranceRecords[userAddress].bankDetails;
    }

    // Function to retrieve certificate details
    function getCertificateDetails(address userAddress)
        public
        view
        onlyUser(userAddress)
        returns (CertificateDetails memory)
    {
        return insuranceRecords[userAddress].certificateDetails;
    }
}
