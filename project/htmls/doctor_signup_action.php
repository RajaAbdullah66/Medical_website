<?php
include "../configuration.php";

$errors = array();
$image = "";
$image_name = "";

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    // Check for required fields and sanitize inputs
    $first_name = isset($_POST["first_name"]) ? trim($_POST["first_name"]) : "";
    $last_name = isset($_POST["last_name"]) ? trim($_POST["last_name"]) : "";
    $gender = isset($_POST["gender"]) ? $_POST["gender"] : "";
    $email = isset($_POST["email"]) ? trim($_POST["email"]) : "";
    $address = isset($_POST["address"]) ? trim($_POST["address"]) : "";
    $tel = isset($_POST["tel"]) ? str_replace("+92", "0", trim($_POST["tel"])) : "";
    $specialization = isset($_POST["specialization"]) ? trim($_POST["specialization"]) : "";
    $startingTime = isset($_POST["startingTime"]) ? trim($_POST["startingTime"]) : "";
    $endingTime = isset($_POST["endingTime"]) ? trim($_POST["endingTime"]) : "";
    $password = isset($_POST["password"]) ? $_POST["password"] : "";

    // Validate inputs
    if (empty($first_name) || !preg_match("/^[a-zA-Z ]*$/", $first_name)) {
        $errors['first_name'] = "First name must contain only letters and spaces.";
    }

    if (empty($last_name) || !preg_match("/^[a-zA-Z ]*$/", $last_name)) {
        $errors['last_name'] = "Last name must contain only letters and spaces.";
    }

    if (empty($email) || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $errors['email'] = "Invalid email format.";
    } else {
        // Check if email already exists
        $stmt = $con->prepare("SELECT D_Id FROM registerdoctor WHERE Email = ?");
        $stmt->bind_param("s", $email);
        $stmt->execute();
        $stmt->store_result();
        if ($stmt->num_rows > 0) {
            $errors['email'] = "Email is already in use. Please try another.";
        }
        $stmt->close();
    }

    if (empty($tel) || !preg_match("/^[0-9]+$/", $tel)) {
        $errors['tel'] = "Phone number must contain only digits.";
    }

    if (empty($password) || strlen($password) < 8) {
        $errors['password'] = "Password must be at least 8 characters long.";
    } else {
        $hashed_password = password_hash($password, PASSWORD_DEFAULT);
    }

    // Handle file upload
    if (isset($_FILES['image']) && $_FILES['image']['error'] === UPLOAD_ERR_OK) {
        $allowed_types = ['image/jpeg', 'image/png', 'image/gif'];
        $file_type = mime_content_type($_FILES['image']['tmp_name']);
        if (!in_array($file_type, $allowed_types)) {
            $errors['image'] = "Only JPG, PNG, and GIF files are allowed.";
        } else {
            $image = addslashes(file_get_contents($_FILES['image']['tmp_name']));
            $image_name = addslashes($_FILES['image']['name']);
        }
    } else {
        $errors['image'] = "Please upload a valid image.";
    }

    // Insert data if no errors
    if (empty($errors)) {
        $stmt = $con->prepare(
            "INSERT INTO registerdoctor (D_Fname, D_Lname, D_Gender, Specialization, StartingHours, EndingHours, PhoneNumber, Address, Email, D_Password, Image, ImageName)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
        );
        $stmt->bind_param(
            "ssssssssssss",
            $first_name, $last_name, $gender, $specialization, $startingTime, $endingTime, $tel, $address, $email, $hashed_password, $image, $image_name
        );

        if ($stmt->execute()) {
            header("Location: doctor_login.php");
            exit;
        } else {
            echo "Error: " . $stmt->error;
        }
        $stmt->close();
    } else {
        // Display validation errors
        foreach ($errors as $error) {
            echo "<p style='color:red;'>$error</p>";
        }
    }
}
?>
