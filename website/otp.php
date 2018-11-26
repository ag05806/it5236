<?php

// Import the application classes
require_once('include/classes.php');

// Create an instance of the Application class
$app = new Application();
$app->setup();

// Declare a set of variables to hold the username and password for the user
//$otp = "";

// Declare an empty array of error messages
$errors = array();

// If someone has clicked their email validation link, then process the request
if ($_SERVER['REQUEST_METHOD'] == 'GET') {

	if (isset($_GET['id'])) {
		
		$success = $app->processOtp($_GET['id'], $errors);
		if ($success) {
			header("location: list.php");
		}

	}

}
?>

<!doctype html>
<html lang="en">
<head>
	<meta charset="utf-8">
	<title>One Time Password</title>
	<meta name="description" content="Ashley Guthrie's personal website for IT 5233">
	<meta name="author" content="Ashley Guthrie">
	<link rel="stylesheet" href="css/style.css">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>

<body>
	<?php include 'include/header.php'; ?>
	<div class="main">
		<h2>One Time Password</h2>

		<?php include('include/messages.php'); ?>
	
		<div>
			<p>Please enter the one time password sent to your email address:</p>
			<form method="get" action="otp.php">
			

				<input type="text" name="id" id="otp"  /*value="<?php echo $otp; ?>"*/ />
				<br/>

				<input type="submit" value="Submit" name="Submit" />
			</form>
		</div>
		
	</div>
	<?php include 'include/footer.php'; ?>
	<script src="js/site.js"></script>
</body>
</html>

