<?php

$page_title = "Check registration";

include 'mysqli_connect.php';

include 'includes/header.html';

include 'includes/navbar.html';

if (isset ($_SESSION['username'])){
	header('location: index.php');
}



if (!isset($_POST['username']) || !isset($_POST['pass'])) {
    include 'includes/error.php';
    exit();
}


$username = $_POST['username'];
$password = $_POST['pass'];

 
$hashedPassword = password_hash($password, PASSWORD_DEFAULT);


$sql1 = "SELECT users_password FROM users WHERE users_username = ?";
$stmt1 = $connection->prepare($sql1);


if (!$stmt1) {
    die("Erreur préparation requête : " . $connection->error);
}

$stmt1->bind_param("s", $username);
$stmt1->execute();
$result1 = $stmt1->get_result();


if ($result1->num_rows == 0) {


    $sql2 = "INSERT INTO users (users_username, users_password) VALUES (?, ?)";
    $stmt2 = $connection->prepare($sql2);

    if (!$stmt2) {
        die("Erreur préparation requête : " . $connection->error);
    }

    $stmt2->bind_param("ss", $username, $hashedPassword);

    if ($stmt2->execute()) {
        include 'includes/new_registration.php';
    } else {
        include 'includes/error.php';
    }

    $stmt2->close();

} else {
    include 'includes/notregistered.php';
}

$stmt1->close();
mysqli_close($connection);

include 'includes/footer.html';

?>