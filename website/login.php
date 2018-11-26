<?php

// Import the application classes
require_once('include/classes.php');

// Create an instance of the Application class
$app = new Application();
$app->setup();

// Declare a set of variables to hold the username and password for the user
$username = "";
$password = "";

// Declare an empty array of error messages
$errors = array();

// If someone has clicked their email validation link, then process the request
if ($_SERVER['REQUEST_METHOD'] == 'GET') {

	if (isset($_GET['id'])) {
		
		$success = $app->processEmailValidation($_GET['id'], $errors);
		if ($success) {
			$message = "Email address validated. You may login.";
		}

	}

}

// If someone is attempting to login, process their request
if ($_SERVER['REQUEST_METHOD'] == 'POST') {

	// Pull the username and password from the <form> POST
	$username = $_POST['username'];
	$password = $_POST['password'];

	// Attempt to login the user and capture the result flag
	$result = $app->login($username, $password, $errors);

	// Check to see if the login attempt succeeded
	if ($result == TRUE) {

		// Redirect the user to the topics page on success
		header("Location: otp.php");
		exit();

	}

}

if (isset($_GET['register']) && $_GET['register']== 'success') {
	$message = "Registration successful. Please check your email. A message has been sent to validate your address.";
}

?>

<!doctype html>
<html lang="en">
<head>
	<meta charset="utf-8">
	<title>anguthrie.me</title>
	<meta name="description" content="Ashley Guthrie's personal website for IT 5233">
	<meta name="author" content="Ashley Guthrie">
	<link rel="stylesheet" href="css/style.css">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>

<!--1. Display Errors if any exists 
	2. Display Login form (sticky):  Username and Password -->

<body>
	<?php include 'include/header.php'; ?>
	<div class="main">
	<h2>Login</h2>

	<?php include('include/messages.php'); ?>
	
	
	<div>
		
		<form method="post" action="login.php" class="logPrompts" id="usernameForm">
			
			<input type="text" name="username" id="usernameField" placeholder="Username" value="<?php echo $username; ?>"/>
			<br/>
			

			<input type="password" name="password" id="password" placeholder="Password" value="<?php echo $password; ?>" />
			<br/>

			<label><input type="checkbox" id="saveLocal">Check here to remember your username</label>
			<br/>

			<input type="submit" value="Login" name="login" />			

			
		</form>
		
	</div>
	<a href="register.php">Need to create an account?</a>
	<br/>
	<a href="reset.php">Forgot your password?</a>
	</div>
	<?php include 'include/footer.php'; ?>

	//<script src="js/site.js"></script>
	
<script  type="text/javascript">

function doSubmit(e) {
	var saveLocal = document.getElementById("saveLocal").checked;
	if (saveLocal) {
		console.log("Saving username to local storage");
		var username = document.getElementById("usernameField").value;
		localStorage.setItem("username",username);
	} else {
		localStorage.removeItem("username");
		sessionStorage.removeItem("username");
	}
}

function doPageLoad(e) {
	console.log("Reading username from local/session storage");
	var usernameLocal = localStorage.getItem("username");
	var usernameSession = sessionStorage.getItem("username");
	if (usernameLocal) {
		document.getElementById("saveLocal").checked = true;
		document.getElementById("usernameField").value = usernameLocal;
	}else {
		//document.getElementById("noSave").checked = true;
	}
}

// Add event listeners for page load and form submit
window.addEventListener("load", doPageLoad, false);
document.getElementById("usernameForm").addEventListener("submit", doSubmit, false);


</script>


</body>
</html>
