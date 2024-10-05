<?php
// Include your database connection file
include 'db_connection.php';

session_start(); // Assuming you have user sessions set up
$owner_id = $_SESSION['user_id']; // Capture the user's ID from the session

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    // Collect form data
    $item_name = $_POST['item_name'];
    $item_type = $_POST['item_type'];
    $item_description = $_POST['item_description'];
    $found_date = $_POST['found_date'];
    $location_type = $_POST['location_type'];
    $block_name = $_POST['block_name'];
    $floor_no = $_POST['floor_no'];
    $room_no = $_POST['room_no'];
    $location_details = $_POST['location_details'];

    // Handle image upload and store its path
    $target_dir = "uploads/";
    $target_file = $target_dir . basename($_FILES["image"]["name"]);
    $imageFileType = strtolower(pathinfo($target_file, PATHINFO_EXTENSION));
    
    // Move uploaded file to server
    move_uploaded_file($_FILES["image"]["tmp_name"], $target_file);

    // Insert product details into the database
    $sql = "INSERT INTO found_items (item_name, item_type, item_description, image_url, found_date, location_type, block_name, floor_no, room_no, location_details, owner_id)
            VALUES ('$item_name', '$item_type', '$item_description', '$target_file', '$found_date', '$location_type', '$block_name', '$floor_no', '$room_no', '$location_details', '$owner_id')";

    if ($conn->query($sql) === TRUE) {
        echo "Item posted successfully!";
    } else {
        echo "Error: " . $sql . "<br>" . $conn->error;
    }

    // Close the database connection
    $conn->close();
}
?>
