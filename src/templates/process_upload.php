<?php
session_start(); // Start session to store data

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    // Collect user data from the form
    $_SESSION['user_details'] = [
        'username' => $_POST['username'],
        'policy_id' => $_POST['policy_id'],
        'aadhaar_number' => $_POST['aadhaar_number'],
        'phone_number' => $_POST['phone_number'],
        'nominee_name' => $_POST['nominee_name'],
        'nominee_aadhaar' => $_POST['nominee_aadhaar'],
        'nominee_phone' => $_POST['nominee_phone'],
        'bank_name' => $_POST['bank_name'],
        'account_number' => $_POST['account_number'],
        'ifsc_code' => $_POST['ifsc_code'],
        'policy_photo' => $_FILES['policy_photo']['name'],
        'reports' => $_FILES['reports']['name']
    ];

    // Redirect to admin page after submission
    header("Location: admin_page.php");
    exit();
}
?>
