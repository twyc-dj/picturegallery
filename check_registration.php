<?php

$page_title = "Check registration";

include 'mysqli_connect.php';
include 'includes/header.html';
include 'includes/navbar.html';

if (isset($_SESSION['username'])) {
    header('location: index.php');
    exit;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {

    // Récupération sécurisée des entrées utilisateur
    $username = trim($_POST['username']);
    $password = trim($_POST['pass']);

    // Vérifier que les champs ne sont pas vides
    if ($username === '' || $password === '') {
        include 'includes/error.php';
        exit;
    }

    // 1. Vérification si le username existe déjà
    $stmt = $connection->prepare("SELECT 1 FROM users WHERE users_username = ? LIMIT 1");
    $stmt->bind_param("s", $username);
    $stmt->execute();
    $stmt->store_result();

    if ($stmt->num_rows > 0) {
        // L’utilisateur existe déjà
        include 'includes/notregistered.php';
        $stmt->close();
    } else {

        // 2. Hachage du mot de passe
        $hashed_password = password_hash($password, PASSWORD_DEFAULT);

        // 3. Insertion sécurisée
        $stmt->close();
        $stmt = $connection->prepare("INSERT INTO users (users_username, users_password) VALUES (?, ?)");
        $stmt->bind_param("ss", $username, $hashed_password);

        if ($stmt->execute()) {
            include 'includes/new_registration.php';
        } else {
            include 'includes/error.php';
        }

        $stmt->close();
    }
}

mysqli_close($connection);
include 'includes/footer.html';

?>