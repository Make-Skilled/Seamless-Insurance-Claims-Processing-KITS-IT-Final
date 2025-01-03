// SPDX-License-Identifier: MIT 
pragma solidity 0.8.19;

contract LifeInsurance {

    struct UserDetails {
        string insurancetype;
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
        string policyPhotoHash;
        string reportsHash;
    }

    struct HospitalDetails {
        string policyId;
        string fullName;
        string contactInfo;
        string userPhotoHash;
    }

    struct PoliceDetails {
        string policyId;
        string fullName;
        string contactInfo;
        string userPhotoHash;
    }

    struct InsuranceRecord {
        UserDetails userDetails;
        NomineeDetails nomineeDetails;
        BankDetails bankDetails;
        CertificateDetails certificateDetails;
        HospitalDetails hospitalDetails;
        PoliceDetails policeDetails;
    }

    mapping(address => InsuranceRecord) private insuranceRecords;
    address[] private userAddresses; // Array to track all user addresses

    event DetailsSubmitted(
        address indexed userAddress,
        string category,
        string description
    );

    function submitUserDetails(
        string memory _insurancetype,
        string memory _username,
        string memory _policyId,
        uint256 _aadhaarNumber,
        string memory _phoneNumber
    ) public {
        if (bytes(insuranceRecords[msg.sender].userDetails.username).length == 0) {
            userAddresses.push(msg.sender);
        }

        insuranceRecords[msg.sender].userDetails = UserDetails(
            _insurancetype,
            _username,
            _policyId,
            _aadhaarNumber,
            _phoneNumber
        );

        emit DetailsSubmitted(msg.sender, "User", "User details updated successfully.");
    }

    function submitNomineeDetails(
        string memory _nomineeName,
        uint256 _nomineeAadhaar,
        string memory _nomineePhone
    ) public {
        insuranceRecords[msg.sender].nomineeDetails = NomineeDetails(
            _nomineeName,
            _nomineeAadhaar,
            _nomineePhone
        );

        emit DetailsSubmitted(msg.sender, "Nominee", "Nominee details updated successfully.");
    }

    function submitBankDetails(
        string memory _bankName,
        string memory _accountNumber,
        string memory _ifscCode
    ) public {
        insuranceRecords[msg.sender].bankDetails = BankDetails(
            _bankName,
            _accountNumber,
            _ifscCode
        );

        emit DetailsSubmitted(msg.sender, "Bank", "Bank details updated successfully.");
    }

    function submitCertificateDetails(
        string memory _policyPhotoHash,
        string memory _reportsHash
    ) public {
        insuranceRecords[msg.sender].certificateDetails = CertificateDetails(
            _policyPhotoHash,
            _reportsHash
        );

        emit DetailsSubmitted(msg.sender, "Certificate", "Certificate details updated successfully.");
    }

    function submitHospitalDetails(
        string memory _policyId,
        string memory _fullName,
        string memory _contactInfo,
        string memory _userPhotoHash
    ) public {
        insuranceRecords[msg.sender].hospitalDetails = HospitalDetails(
            _policyId,
            _fullName,
            _contactInfo,
            _userPhotoHash
        );

        emit DetailsSubmitted(msg.sender, "Hospital", "Hospital details updated successfully.");
    }

    function submitPoliceDetails(
        string memory _policyId,
        string memory _fullName,
        string memory _contactInfo,
        string memory _userPhotoHash
    ) public {
        insuranceRecords[msg.sender].policeDetails = PoliceDetails(
            _policyId,
            _fullName,
            _contactInfo,
            _userPhotoHash
        );

        emit DetailsSubmitted(msg.sender, "Police", "Police details updated successfully.");
    }

    function getUserDetails(address userAddress)
        public
        view
        returns (UserDetails memory)
    {
        return insuranceRecords[userAddress].userDetails;
    }

    function getNomineeDetails(address userAddress)
        public
        view
        returns (NomineeDetails memory)
    {
        return insuranceRecords[userAddress].nomineeDetails;
    }

    function getBankDetails(address userAddress)
        public
        view
        returns (BankDetails memory)
    {
        return insuranceRecords[userAddress].bankDetails;
    }

    function getCertificateDetails(address userAddress)
        public
        view
        returns (CertificateDetails memory)
    {
        return insuranceRecords[userAddress].certificateDetails;
    }

    function getHospitalDetails(address userAddress)
        public
        view
        returns (HospitalDetails memory)
    {
        return insuranceRecords[userAddress].hospitalDetails;
    }

    function getPoliceDetails(address userAddress)
        public
        view
        returns (PoliceDetails memory)
    {
        return insuranceRecords[userAddress].policeDetails;
    }

    // Function to retrieve all user records
    function getAllUsers() public view returns (InsuranceRecord[] memory) {
        InsuranceRecord[] memory allRecords = new InsuranceRecord[](userAddresses.length);

        for (uint256 i = 0; i < userAddresses.length; i++) {
            allRecords[i] = insuranceRecords[userAddresses[i]];
        }

        return allRecords;
    }

    // Function to retrieve all user addresses
    function getUserAddresses() public view returns (address[] memory) {
        return userAddresses;
    }
}
