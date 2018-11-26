<?php

// Import the application classes
require_once('include/classes.php');

// Create an instance of the Application class
$app = new Application();
$app->setup();

// Get the name of the file to display the contents of
$name = $_GET["file"];

?>

<!doctype html>
<html lang="en">
<head>
	<meta charset="utf-8">
	<title>Eat It</title>
	<meta name="description" content="Ashley Guthrie's personal website for IT 5233">
	<meta name="author" content="Ashley Guthrie">
	<link rel="stylesheet" href="css/style.css">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>

<!--1. Display Errors if any exists 
	2. If no errors display things -->
<body>
	<?php include 'include/header.php'; ?>
	<div class="main">
		<h2>User Guide</h2>
		<div>
			<?php echo $app->getFile($name); ?>
		</div>
	</div>
	
</body>
</html>
