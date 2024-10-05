<?php
// Connection to MySQL
$servername = "localhost";
$username = "root";
$password = "tsee12345";
$dbname = "lost_and_found";

// Create connection - mysqli is provided by php for database interaction
$conn = new mysqli($servername, $username, $password, $dbname);

// Check connection - $conn->connect_error contains the error message
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    // Get form inputs
    $reg = $_POST['reg'];
    $student_name = $_POST['student_name'];
    $student_type = $_POST['student_type'];
    $phone = $_POST['phone'];
    $email = $_POST['email'];
    $address = $_POST['address'];
    $password = $_POST['signup-password'];
    $confirm_password = $_POST['confirm-password'];

    // Check if passwords match
    if ($password !== $confirm_password) {
        echo "Passwords do not match!";
        exit;
    }

    // Hash the password
    $hashed_password = password_hash($password, PASSWORD_BCRYPT);   //PASSWORD_BCRYPT is a hashing algo

    // Prepare SQL statement
    $stmt = $conn->prepare("INSERT INTO users (reg, student_name, student_type, phone, email, address, password1) VALUES (?, ?, ?, ?, ?, ?, ?)");
    $stmt->bind_param("sssisss", $reg, $student_name, $student_type, $phone, $email, $address, $hashed_password);

    // Execute the statement
    if ($stmt->execute()) {
        echo "Signup successful!";
        header("Location: login.html");
    } else {
        error_log("Database error: " . $stmt->error); // Log error
        echo "Error: " . $stmt->error;
    }

    // Close connections
    $stmt->close();
    $conn->close();
}
?>
