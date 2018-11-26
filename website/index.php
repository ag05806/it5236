<?php
	
// Import the application classes
require_once('include/classes.php');

// Create an instance of the Application class
$app = new Application();
$app->setup();

// Declare an empty array of error messages
$errors = array();

?>

<!doctype html>
<html lang="en">
<head>
	<meta charset="utf-8">
	<title>Eat It</title>
	<meta name="description" content="Ashley Guthrie's website for IT 5236">
	<meta name="author" content="Ashley Guthrie">
	<link rel="stylesheet" href="css/style.css">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body>
	<?php include 'include/header.php'; ?>
	<div class="main">
		<h2>Manage YOUR Favorite Bars and Restaurants</h2>
		<p>
			This is a list-oriented web application to let users store information on their favorite bars and restaurants.
			If you have an account, you may <a href="login.php">login</a>. Otherwise, please or proceed to the 
			<a href="register.php">registration page</a>.
		</p>
	</div>
	<?php include 'include/footer.php'; ?>
	<script src="js/site.js"></script>
</body>
</html>
