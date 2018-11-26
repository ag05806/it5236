<?php

if (file_exists(getcwd() . "/include/credentials.php")) {
    require('credentials.php');
} else {
    echo "Application has not been configured. Copy and edit the credentials-sample.php file to credentials.php.";
    exit();
}

class Application {
    
    public $debugMessages = [];
    
    public function setup() {
        
        // Check to see if the client has a cookie called "debug" with a value of "true"
        // If it does, turn on error reporting
        if ($_COOKIE['debug'] == "true") {
            ini_set('display_errors', 1);
            ini_set('display_startup_errors', 1);
            error_reporting(E_ALL);
        }
    }
    
    // Writes a message to the debug message array for printing in the footer.
    public function debug($message) {
        $this->debugMessages[] = $message;
    }
    
    // Creates a database connection
    protected function getConnection() {
        
        // Import the database credentials
        $credentials = new Credentials();
        
        // Create the connection
        try {
            $dbh = new PDO("mysql:host=$credentials->servername;dbname=$credentials->serverdb", $credentials->serverusername, $credentials->serverpassword);
        } catch (PDOException $e) {
            print "Error connecting to the database.";
            die();
        }
        
        // Return the newly created connection
        return $dbh;
    }
    
    public function auditlog($context, $message, $priority = 0, $userid = NULL){
        
        // Declare an errors array
        $errors = [];
       
        
        // If a user is logged in, get their userid
        if ($userid == NULL) {
            
            $user = $this->getSessionUser($errors, TRUE);
            if ($user != NULL) {
                $userid = $user["userid"];
            }
            
        }
        
        $ipaddress = $_SERVER["REMOTE_ADDR"];
        
        if (is_array($message)){
            $message = implode( ",", $message);
        }
        
                // Only try to insert the data into the database if there are no validation errors
        if (sizeof($errors) == 0) {
            
  

			$url = "https://2rnhwtr7e6.execute-api.us-east-2.amazonaws.com/default/auditlog";
			$data = array(
				'message'=>$message,
				'priority'=>$priority,
				'context'=>$context
			);
			$data_json = json_encode($data);

			$ch = curl_init();
			curl_setopt($ch, CURLOPT_URL, $url);
			curl_setopt($ch, CURLOPT_HTTPHEADER, array('x-api-key:3tEg1MXoeo4K4Q7mtVVuW1quD30CmHSw6BQB3hSY','Content-Type: application/json','Content-Length: ' . strlen($data_json)));
			curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'POST');
			curl_setopt($ch, CURLOPT_POSTFIELDS, $data_json);
			curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
			$response  = curl_exec($ch);
			$httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);

			if ($response === FALSE) {
				$errors[] = "An unexpected failure occurred contacting the web service.";
			} else {

				if($httpCode == 400) {
					
					// JSON was double-encoded, so it needs to be double decoded
					$errorsList = json_decode(json_decode($response))->errors;
					foreach ($errorsList as $err) {
						$errors[] = $err;
					}
					if (sizeof($errors) == 0) {
						$errors[] = "Bad input";
					}

				} else if($httpCode == 500) {

					$errorsList = json_decode(json_decode($response))->errors;
					foreach ($errorsList as $err) {
						$errors[] = $err;
					}
					if (sizeof($errors) == 0) {
						$errors[] = "Server error";
					}

				} else if($httpCode == 200) {

					$this->sendValidationEmail($userid, $email, $errors);

				}

			}
			
			curl_close($ch);

        } else {
            $this->auditlog($context, $message, $priority = 0, $userid = NULL);
        }
        
        // Return TRUE if there are no errors, otherwise return FALSE
        if (sizeof($errors) == 0){
            return TRUE;
        } else {
            return FALSE;
        }
    }
  
    
    protected function validateUsername($username, &$errors) {
        if (empty($username)) {
            $errors[] = "Missing username";
        } else if (strlen(trim($username)) < 3) {
            $errors[] = "Username must be at least 3 characters";
        } else if (strpos($username, "@")) {
            $errors[] = "Username may not contain an '@' sign";
        }
    }
    
    protected function validatePassword($password, &$errors) {
        if (empty($password)) {
            $errors[] = "Missing password";
        } else if (strlen(trim($password)) < 8) {
            $errors[] = "Password must be at least 8 characters";
        }
    }
    
    protected function validateEmail($email, &$errors) {
        if (empty($email)) {
            $errors[] = "Missing email";
        } 
    }
    
    
    // Registers a new user
    public function register($username, $password, $email, $registrationcode, &$errors) {
        
        $this->auditlog("register", "attempt: $username, $email, $registrationcode");
        
        // Validate the user input
        $this->validateUsername($username, $errors);
        $this->validatePassword($password, $errors);
        $this->validateEmail($email, $errors);
        if (empty($registrationcode)) {
            $errors[] = "Missing registration code";
        }
        
        // Only try to insert the data into the database if there are no validation errors
        if (sizeof($errors) == 0) {
            
            // Hash the user's password
            $passwordhash = password_hash($password, PASSWORD_DEFAULT);
            
            // Create a new user ID
            $userid = bin2hex(random_bytes(16));

			$url = "https://2rnhwtr7e6.execute-api.us-east-2.amazonaws.com/default/registerUser";
			$data = array(
				'userid'=>$userid,
				'username'=>$username,
				'passwordHash'=>$passwordhash,
				'email'=>$email,
				'registrationcode'=>$registrationcode
			);
			$data_json = json_encode($data);

			$ch = curl_init();
			curl_setopt($ch, CURLOPT_URL, $url);
			curl_setopt($ch, CURLOPT_HTTPHEADER, array('x-api-key:3tEg1MXoeo4K4Q7mtVVuW1quD30CmHSw6BQB3hSY','Content-Type: application/json','Content-Length: ' . strlen($data_json)));
			curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'POST');
			curl_setopt($ch, CURLOPT_POSTFIELDS, $data_json);
			curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
			$response  = curl_exec($ch);
			$httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);

			if ($response === FALSE) {
				$errors[] = "An unexpected failure occurred contacting the web service.";
			} else {

				if($httpCode == 400) {
					
					// JSON was double-encoded, so it needs to be double decoded
					$errorsList = json_decode(json_decode($response))->errors;
					foreach ($errorsList as $err) {
						$errors[] = $err;
					}
					if (sizeof($errors) == 0) {
						$errors[] = "Bad input";
					}

				} else if($httpCode == 500) {

					$errorsList = json_decode(json_decode($response))->errors;
					foreach ($errorsList as $err) {
						$errors[] = $err;
					}
					if (sizeof($errors) == 0) {
						$errors[] = "Server error";
					}

				} else if($httpCode == 200) {

					$this->sendValidationEmail($userid, $email, $errors);

				}

			}
			
			curl_close($ch);

        } else {
            $this->auditlog("register validation error", $errors);
        }
        
        // Return TRUE if there are no errors, otherwise return FALSE
        if (sizeof($errors) == 0){
            return TRUE;
        } else {
            return FALSE;
        }
    }
	

  /*  // Registers a new user
    public function register($username, $password, $email, $registrationcode, &$errors) {
        
        $this->auditlog("register", "attempt: $username, $email, $registrationcode");
        
        // Validate the user input
        $this->validateUsername($username, $errors);
        $this->validatePassword($password, $errors);
        $this->validateEmail($email, $errors);
        if (empty($registrationcode)) {
            $errors[] = "Missing registration code";
        }
        
        // Only try to insert the data into the database if there are no validation errors
        if (sizeof($errors) == 0) {
            
            // Connect to the database
            $dbh = $this->getConnection();
            
            // Check the registration codes table for the code provided
            $goodcode = FALSE;
            $sql = "SELECT COUNT(*) AS codecount FROM registrationcodes WHERE LOWER(registrationcode) = LOWER(:code)";
            $stmt = $dbh->prepare($sql);
            $stmt->bindParam(':code', $registrationcode);
            $result = $stmt->execute();
            if ($result) {
                if ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
                    if ($row["codecount"] == 1) {
                        $goodcode = TRUE;
                    }
                }
            } else {
                $this->debug($stmt->errorInfo());
            }
            
            // If the code is bad, then return error
            if (!$goodcode) {
                $errors[] = "Bad registration code";
                $this->auditlog("register", "bad registration code: $registrationcode");
                
            } else {
                
                // Hash the user's password
                $passwordhash = password_hash($password, PASSWORD_DEFAULT);
                
                // Create a new user ID
                $userid = bin2hex(random_bytes(16));
                
                // Construct a SQL statement to perform the insert operation
                $sql = "INSERT INTO users (userid, username, passwordhash, email) " .
                    "VALUES (:userid, :username, :passwordhash, :email)";
                
                // Run the SQL insert and capture the result code
                $stmt = $dbh->prepare($sql);
                $stmt->bindParam(':userid', $userid);
                $stmt->bindParam(':username', $username);
                $stmt->bindParam(':passwordhash', $passwordhash);
                $stmt->bindParam(':email', $email);
                $result = $stmt->execute();
                
                // If the query did not run successfully, add an error message to the list
                if ($result === FALSE) {
                    
                    $arr = $stmt->errorInfo();
                    $this->debug($stmt->errorInfo());
                    
                    // Check for duplicate userid/username/email
                    if ($arr[1] == 1062) {
                        if (substr($arr[2], -7, 6) == "userid") {
                            $errors[] = "An unexpected registration error occurred. Please try again in a few minutes.";
                            $this->debug($stmt->errorInfo());
                            $this->auditlog("register error", $stmt->errorInfo());
                            
                        } else if (substr($arr[2], -9, 8) == "username") {
                            $errors[] = "That username is not available.";
                            $this->auditlog("register", "duplicate username: $username");
                        } else if (substr($arr[2], -6, 5) == "email") {
                            $errors[] = "That email has already been registered.";
                            $this->auditlog("register", "duplicate email: $email");
                        } else {
                            $errors[] = "An unexpected error occurred.";
                            $this->debug($stmt->errorInfo());
                            $this->auditlog("register error", $stmt->errorInfo());
                        }
                    } else {
                        $errors[] = "An unexpected error occurred.";
                        $this->debug($stmt->errorInfo());
                        $this->auditlog("register error", $stmt->errorInfo());
                    }
                } else {
                    // Construct a SQL statement to perform the insert operation
                    $sql = "INSERT INTO userregistrations (userid, registrationcode) " .
                        "VALUES (:userid, :registrationcode)";
                    
                    // Run the SQL insert and capture the result code
                    $stmt = $dbh->prepare($sql);
                    $stmt->bindParam(':userid', $userid);
                    $stmt->bindParam(':registrationcode', $registrationcode);
                    $result = $stmt->execute();
                    
                    // If the query did not run successfully, add an error message to the list
                    if ($result === FALSE) {
                        
                        $arr = $stmt->errorInfo();
                        $this->debug($stmt->errorInfo());
                        
                        if ($arr[1] == 1062) {
                            $errors[] = "User already registered for course.";
                            $this->auditlog("register", "duplicate course registration: $userid, $registrationcode");
                        }
                        
                    } else {
                        
                        $this->auditlog("register", "success: $userid, $username, $email");
                        $this->sendValidationEmail($userid, $email, $errors);
                        
                    }
                    
                }
                
            }
            
            // Close the connection
            $dbh = NULL;
            
        } else {
            $this->auditlog("register validation error", $errors);
        }
        
        // Return TRUE if there are no errors, otherwise return FALSE
        if (sizeof($errors) == 0){
            return TRUE;
        } else {
            return FALSE;
        }
    } */
    
    // Send an email to validate the address
    protected function sendValidationEmail($userid, $email, &$errors) {
        
        
        $this->auditlog("sendValidationEmail", "Sending message to $email");
        
        $validationid = bin2hex(random_bytes(16));
     
     // Only try to insert the data into the database if there are no validation errors
        if (sizeof($errors) == 0) {
            
            // Hash the user's password
            $passwordhash = password_hash($password, PASSWORD_DEFAULT);
            
            // Create a new user ID
            $userid = bin2hex(random_bytes(16));

			$url = "https://2rnhwtr7e6.execute-api.us-east-2.amazonaws.com/default/sendValidationEmail";
			$data = array(
				'userid'=>$userid,
				'email'=>$email
			);
			$data_json = json_encode($data);

			$ch = curl_init();
			curl_setopt($ch, CURLOPT_URL, $url);
			curl_setopt($ch, CURLOPT_HTTPHEADER, array('x-api-key:3tEg1MXoeo4K4Q7mtVVuW1quD30CmHSw6BQB3hSY','Content-Type: application/json','Content-Length: ' . strlen($data_json)));
			curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'PUT');
			curl_setopt($ch, CURLOPT_POSTFIELDS, $data_json);
			curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
			$response  = curl_exec($ch);
			$httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);

			if ($response === FALSE) {
				$errors[] = "An unexpected failure occurred contacting the web service.";
			} else {

				if($httpCode == 400) {
					
					// JSON was double-encoded, so it needs to be double decoded
					$errorsList = json_decode(json_decode($response))->errors;
					foreach ($errorsList as $err) {
						$errors[] = $err;
					}
					if (sizeof($errors) == 0) {
						$errors[] = "Bad input";
					}

				} else if($httpCode == 500) {

					$errorsList = json_decode(json_decode($response))->errors;
					foreach ($errorsList as $err) {
						$errors[] = $err;
					}
					if (sizeof($errors) == 0) {
						$errors[] = "Server error";
					}

				} else if($httpCode == 200) {

					$this->sendValidationEmail($userid, $email, $errors);

				}

			}
			
			curl_close($ch);

        } else {
            $this->auditlog("register validation error", $errors);
        }
        
        // Return TRUE if there are no errors, otherwise return FALSE
        if (sizeof($errors) == 0){
            return TRUE;
        } else {
            return FALSE;
        }
        
       
    }
    
    
    // Creates a new session in the database for the specified user
    public function newSession($userid, &$errors, $registrationcode = NULL) {
        
        // Check for a valid userid
        if (empty($userid)) {
            $errors[] = "Missing userid";
            $this->auditlog("session", "missing userid");
        }
        
        // Only try to query the data into the database if there are no validation errors
        if (sizeof($errors) == 0) {
            
            if ($registrationcode == NULL) {
                $regs = $this->getUserRegistrations($userid, $errors);
                $reg = $regs[0];
                $this->auditlog("session", "logging in user with first reg code $reg");
                $registrationcode = $regs[0];
            }
            
            
            // Only try to insert the data into the database if there are no validation errors
        if (sizeof($errors) == 0) {
          
            // Create a new session ID
            $sessionid = bin2hex(random_bytes(25));
            
			$url = "https://2rnhwtr7e6.execute-api.us-east-2.amazonaws.com/default/newSession";
			$data = array(
				'userid'=>$userid,
				'registrationcode'=>$registrationcode
			);
			$data_json = json_encode($data);

			$ch = curl_init();
			curl_setopt($ch, CURLOPT_URL, $url);
			curl_setopt($ch, CURLOPT_HTTPHEADER, array('x-api-key:3tEg1MXoeo4K4Q7mtVVuW1quD30CmHSw6BQB3hSY','Content-Type: application/json','Content-Length: ' . strlen($data_json)));
			curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'POST');
			curl_setopt($ch, CURLOPT_POSTFIELDS, $data_json);
			curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
			$response  = curl_exec($ch);
			$httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);

			if ($response === FALSE) {
				$errors[] = "An unexpected failure occurred contacting the web service.";
			} else {

				if($httpCode == 400) {
					
					// JSON was double-encoded, so it needs to be double decoded
					$errorsList = json_decode(json_decode($response))->errors;
					foreach ($errorsList as $err) {
						$errors[] = $err;
					}
					if (sizeof($errors) == 0) {
						$errors[] = "Bad input";
					}

				} else if($httpCode == 500) {

					$errorsList = json_decode(json_decode($response))->errors;
					foreach ($errorsList as $err) {
						$errors[] = $err;
					}
					if (sizeof($errors) == 0) {
						$errors[] = "Server error";
					}

				} else if($httpCode == 200) {

					$this->newSession ($userid, &$errors, $registrationcode = NULL);

				}

			}
			
			curl_close($ch);

        } else {
            $this->auditlog("new session error", $errors);
        }
        
        // Return TRUE if there are no errors, otherwise return FALSE
        if (sizeof($errors) == 0){
            return TRUE;
        } else {
            return FALSE;
        }
            
            // If the query did not run successfully, add an error message to the list
            if ($result === FALSE) {
                
                $errors[] = "An unexpected error occurred";
                $this->debug($stmt->errorInfo());
                $this->auditlog("new session error", $stmt->errorInfo());
                return NULL;
                
            } else {
                
                // Store the session ID as a cookie in the browser
                setcookie('sessionid', $sessionid, time()+60*60*24*30);
                $this->auditlog("session", "new session id: $sessionid for user = $userid");
                
                // Return the session ID
                return $sessionid;
                
            }
            
        }
        
    }
    
    public function getUserRegistrations($userid, &$errors) {
        
        // Assume an empty list of regs
        $regs = array();
        
      // Only try to insert the data into the database if there are no validation errors
        if (sizeof($errors) == 0) {

			$url = "https://2rnhwtr7e6.execute-api.us-east-2.amazonaws.com/default/getUserRegistrations";
			$data = array(
				'userid'=>$userid
			);
			$data_json = json_encode($data);

			$ch = curl_init();
			curl_setopt($ch, CURLOPT_URL, $url);
			curl_setopt($ch, CURLOPT_HTTPHEADER, array('x-api-key:3tEg1MXoeo4K4Q7mtVVuW1quD30CmHSw6BQB3hSY','Content-Type: application/json','Content-Length: ' . strlen($data_json)));
			curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'GET');
			curl_setopt($ch, CURLOPT_POSTFIELDS, $data_json);
			curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
			$response  = curl_exec($ch);
			$httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);

			if ($response === FALSE) {
				$errors[] = "An unexpected failure occurred contacting the web service.";
			} else {

				if($httpCode == 400) {
					
					// JSON was double-encoded, so it needs to be double decoded
					$errorsList = json_decode(json_decode($response))->errors;
					foreach ($errorsList as $err) {
						$errors[] = $err;
					}
					if (sizeof($errors) == 0) {
						$errors[] = "Bad input";
					}

				} else if($httpCode == 500) {

					$errorsList = json_decode(json_decode($response))->errors;
					foreach ($errorsList as $err) {
						$errors[] = $err;
					}
					if (sizeof($errors) == 0) {
						$errors[] = "Server error";
					}

				} else if($httpCode == 200) {

					$this->getUserRegistrations($userid, $errors);

				}

			}
			
			curl_close($ch);

        } else {
            $this->auditlog("fetching error", $errors);
        }
        
        // Return TRUE if there are no errors, otherwise return FALSE
        if (sizeof($errors) == 0){
            return TRUE;
        } else {
            return FALSE;
        }
        
        // Return the list of users
        return $regs;
    }
    
    // Updates a password in the database and will return the $errors array listing any errors encountered
    public function updateUserPassword($userid, $password, &$errors) {
        
        // Validate the user input
        if (empty($userid)) {
            $errors[] = "Missing userid";
        }
        $this->validatePassword($password, $errors);
    
    // Only try to insert the data into the database if there are no validation errors
        if (sizeof($errors) == 0) {
            
            // Hash the user's password
            $passwordhash = password_hash($password, PASSWORD_DEFAULT);

			$url = "https://2rnhwtr7e6.execute-api.us-east-2.amazonaws.com/default/updatePassword";
			$data = array(
				'userid'=>$userid,
				'username'=>$username,
				'passwordHash'=>$passwordhash,
				'email'=>$email,
				'registrationcode'=>$registrationcode
			);
			$data_json = json_encode($data);

			$ch = curl_init();
			curl_setopt($ch, CURLOPT_URL, $url);
			curl_setopt($ch, CURLOPT_HTTPHEADER, array('x-api-key:3tEg1MXoeo4K4Q7mtVVuW1quD30CmHSw6BQB3hSY','Content-Type: application/json','Content-Length: ' . strlen($data_json)));
			curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'PUT');
			curl_setopt($ch, CURLOPT_POSTFIELDS, $data_json);
			curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
			$response  = curl_exec($ch);
			$httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);

			if ($response === FALSE) {
				$errors[] = "An unexpected failure occurred contacting the web service.";
			} else {

				if($httpCode == 400) {
					
					// JSON was double-encoded, so it needs to be double decoded
					$errorsList = json_decode(json_decode($response))->errors;
					foreach ($errorsList as $err) {
						$errors[] = $err;
					}
					if (sizeof($errors) == 0) {
						$errors[] = "Bad input";
					}

				} else if($httpCode == 500) {

					$errorsList = json_decode(json_decode($response))->errors;
					foreach ($errorsList as $err) {
						$errors[] = $err;
					}
					if (sizeof($errors) == 0) {
						$errors[] = "Server error";
					}

				} else if($httpCode == 200) {

					$this->updateUserPassword($userid, $password, &$errors);

				}

			}
			
			curl_close($ch);

        } else {
            $this->auditlog("password update error", $errors);
        }
        
        // Return TRUE if there are no errors, otherwise return FALSE
        if (sizeof($errors) == 0){
            return TRUE;
        } else {
            return FALSE;
        }
        
      } else {
            
            $this->auditlog("updateUserPassword validation error", $errors);
            
        }
    
    // Removes the specified password reset entry in the database, as well as any expired ones
    // Does not retrun errors, as the user should not be informed of these problems
    protected function clearPasswordResetRecords($passwordresetid) {
        
        // Only try to delete the data if there are no errors
       
        if (sizeof($errors) == 0) {
			$url = "https://2rnhwtr7e6.execute-api.us-east-2.amazonaws.com/default/clearPasswordResetRecords";
			$data = array(
				'passwordresetid'=>$passwordresetid
			);
			$data_json = json_encode($data);

			$ch = curl_init();
			curl_setopt($ch, CURLOPT_URL, $url);
			curl_setopt($ch, CURLOPT_HTTPHEADER, array('x-api-key:3tEg1MXoeo4K4Q7mtVVuW1quD30CmHSw6BQB3hSY','Content-Type: application/json','Content-Length: ' . strlen($data_json)));
			curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'DELETE');
			curl_setopt($ch, CURLOPT_POSTFIELDS, $data_json);
			curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
			$response  = curl_exec($ch);
			$httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);

			if ($response === FALSE) {
				$errors[] = "An unexpected failure occurred contacting the web service.";
			} else {

				if($httpCode == 400) {
					
					// JSON was double-encoded, so it needs to be double decoded
					$errorsList = json_decode(json_decode($response))->errors;
					foreach ($errorsList as $err) {
						$errors[] = $err;
					}
					if (sizeof($errors) == 0) {
						$errors[] = "Bad input";
					}

				} else if($httpCode == 500) {

					$errorsList = json_decode(json_decode($response))->errors;
					foreach ($errorsList as $err) {
						$errors[] = $err;
					}
					if (sizeof($errors) == 0) {
						$errors[] = "Server error";
					}

				} else if($httpCode == 200) {

					$this->clearPasswordResetRecords($passwordresetid);

				}

			}
			
			curl_close($ch);

        } else {
            $this->auditlog("password reset clearing error", $errors);
        }
        
        // Return TRUE if there are no errors, otherwise return FALSE
        if (sizeof($errors) == 0){
            return TRUE;
        } else {
            return FALSE;
        }
        
    }
    
    // Retrieves an existing session from the database for the specified user
    public function getSessionUser(&$errors, $suppressLog=FALSE) {
        
        // Get the session id cookie from the browser
        $sessionid = NULL;
        $user = NULL;
        
        // Check for a valid session ID
        if (isset($_COOKIE['sessionid'])) {
            
            $sessionid = $_COOKIE['sessionid'];
            
            // Only try to get the data if there are no errors
            if (sizeof($errors) == 0) {
            

			$url = "https://2rnhwtr7e6.execute-api.us-east-2.amazonaws.com/default/getSessionUser";
			$data = array(
				'usersessionid'=>$sessionid,
                'user'=>$user
			);
			$data_json = json_encode($data);

			$ch = curl_init();
			curl_setopt($ch, CURLOPT_URL, $url);
			curl_setopt($ch, CURLOPT_HTTPHEADER, array('x-api-key:3tEg1MXoeo4K4Q7mtVVuW1quD30CmHSw6BQB3hSY','Content-Type: application/json','Content-Length: ' . strlen($data_json)));
			curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'GET');
			curl_setopt($ch, CURLOPT_POSTFIELDS, $data_json);
			curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
			$response  = curl_exec($ch);
			$httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);

			if ($response === FALSE) {
				$errors[] = "An unexpected failure occurred contacting the web service.";
			} else {

				if($httpCode == 400) {
					
					// JSON was double-encoded, so it needs to be double decoded
					$errorsList = json_decode(json_decode($response))->errors;
					foreach ($errorsList as $err) {
						$errors[] = $err;
					}
					if (sizeof($errors) == 0) {
						$errors[] = "Bad input";
					}

				} else if($httpCode == 500) {

					$errorsList = json_decode(json_decode($response))->errors;
					foreach ($errorsList as $err) {
						$errors[] = $err;
					}
					if (sizeof($errors) == 0) {
						$errors[] = "Server error";
					}

				} else if($httpCode == 200) {

					$this->getSessionUser(&$errors, $suppressLog=FALSE);

				}

			}
			
			curl_close($ch);

        } else {
            $this->auditlog("user session error", $errors);
        }
        
        // Return TRUE if there are no errors, otherwise return FALSE
        if (sizeof($errors) == 0){
            return TRUE;
        } else {
            return FALSE;
        }
            
             
                
            }
         return $user;   
	}
    
    // Retrieves an existing session from the database for the specified user
   public function isAdmin(&$errors, $userid) {
        
        // Check for a valid user ID
        if (empty($userid)) {
            $errors[] = "Missing userid";
            return FALSE;
        }
     
        if (sizeof($errors) == 0) {
            
			$url = "https://2rnhwtr7e6.execute-api.us-east-2.amazonaws.com/default/isAdmin";
			$data = array(
				'userid'=>$userid
			);
			$data_json = json_encode($data);

			$ch = curl_init();
			curl_setopt($ch, CURLOPT_URL, $url);
			curl_setopt($ch, CURLOPT_HTTPHEADER, array('x-api-key:3tEg1MXoeo4K4Q7mtVVuW1quD30CmHSw6BQB3hSY','Content-Type: application/json','Content-Length: ' . strlen($data_json)));
			curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'GET');
			curl_setopt($ch, CURLOPT_POSTFIELDS, $data_json);
			curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
			$response  = curl_exec($ch);
			$httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);

			if ($response === FALSE) {
				$errors[] = "An unexpected failure occurred contacting the web service.";
			} else {

				if($httpCode == 400) {
					
					// JSON was double-encoded, so it needs to be double decoded
					$errorsList = json_decode(json_decode($response))->errors;
					foreach ($errorsList as $err) {
						$errors[] = $err;
					}
					if (sizeof($errors) == 0) {
						$errors[] = "Bad input";
					}

				} else if($httpCode == 500) {

					$errorsList = json_decode(json_decode($response))->errors;
					foreach ($errorsList as $err) {
						$errors[] = $err;
					}
					if (sizeof($errors) == 0) {
						$errors[] = "Server error";
					}

				} else if($httpCode == 200) {

					$this->isAdmin(&$errors, $userid);

				}

			}
			
			curl_close($ch);

        } else {
            $this->auditlog("register validation error", $errors);
        }
        
        // Return TRUE if there are no errors, otherwise return FALSE
        if (sizeof($errors) == 0){
            return TRUE;
        } else {
            return FALSE;
        }
            
        }
    
    // Logs in an existing user and will return the $errors array listing any errors encountered
    public function login($username, $password, &$errors) {
        
        $this->debug("Login attempted");
        $this->auditlog("login", "attempt: $username, password length = ".strlen($password));
        
        // Validate the user input
        if (empty($username)) {
            $errors[] = "Missing username";
        }
        if (empty($password)) {
            $errors[] = "Missing password";
        }
        
              if (sizeof($errors) == 0) {
			$url = "https://2rnhwtr7e6.execute-api.us-east-2.amazonaws.com/default/loginUser";
			$data = array(
				'username'=>$username,
				'password'=>$password
			);
			$data_json = json_encode($data);

			$ch = curl_init();
			curl_setopt($ch, CURLOPT_URL, $url);
			curl_setopt($ch, CURLOPT_HTTPHEADER, array('x-api-key:3tEg1MXoeo4K4Q7mtVVuW1quD30CmHSw6BQB3hSY','Content-Type: application/json','Content-Length: ' . strlen($data_json)));
			curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'POST');
			curl_setopt($ch, CURLOPT_POSTFIELDS, $data_json);
			curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
			$response  = curl_exec($ch);
			$httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);

			if ($response === FALSE) {
				$errors[] = "An unexpected failure occurred contacting the web service.";
			} else {

				if($httpCode == 400) {
					
					// JSON was double-encoded, so it needs to be double decoded
					$errorsList = json_decode(json_decode($response))->errors;
					foreach ($errorsList as $err) {
						$errors[] = $err;
					}
					if (sizeof($errors) == 0) {
						$errors[] = "Bad input";
					}

				} else if($httpCode == 500) {

					$errorsList = json_decode(json_decode($response))->errors;
					foreach ($errorsList as $err) {
						$errors[] = $err;
					}
					if (sizeof($errors) == 0) {
						$errors[] = "Server error";
					}

				} else if($httpCode == 200) {

					$this->login($username, $password, &$errors);

				}

			}
			
			curl_close($ch);

        } else {
            $this->auditlog("login error", $errors);
        }
        
        // Return TRUE if there are no errors, otherwise return FALSE
        if (sizeof($errors) == 0){
            return TRUE;
        } else {
            return FALSE;
        }
    }
    
    // Logs out the current user based on session ID
     public function logout() {
        
        $sessionid = $_COOKIE['sessionid'];
        
        // Only try to query the data into the database if there are no validation errors
           if (!empty($sessionid)) == 0) {
           
			$url = "https://2rnhwtr7e6.execute-api.us-east-2.amazonaws.com/default/logout";
			$data = array(
				'usersessionid'=>$sessionid
			);
			$data_json = json_encode($data);

			$ch = curl_init();
			curl_setopt($ch, CURLOPT_URL, $url);
			curl_setopt($ch, CURLOPT_HTTPHEADER, array('x-api-key:3tEg1MXoeo4K4Q7mtVVuW1quD30CmHSw6BQB3hSY','Content-Type: application/json','Content-Length: ' . strlen($data_json)));
			curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'DELETE');
			curl_setopt($ch, CURLOPT_POSTFIELDS, $data_json);
			curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
			$response  = curl_exec($ch);
			$httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);

			if ($response === FALSE) {
				$errors[] = "An unexpected failure occurred contacting the web service.";
			} else {

				if($httpCode == 400) {
					
					// JSON was double-encoded, so it needs to be double decoded
					$errorsList = json_decode(json_decode($response))->errors;
					foreach ($errorsList as $err) {
						$errors[] = $err;
					}
					if (sizeof($errors) == 0) {
						$errors[] = "Bad input";
					}

				} else if($httpCode == 500) {

					$errorsList = json_decode(json_decode($response))->errors;
					foreach ($errorsList as $err) {
						$errors[] = $err;
					}
					if (sizeof($errors) == 0) {
						$errors[] = "Server error";
					}

				} else if($httpCode == 200) {

					$this->logout();

				}

			}
			
			curl_close($ch);

        } else {
            $this->auditlog("logout error", $errors);
        }
        
        // Return TRUE if there are no errors, otherwise return FALSE
        if (sizeof($errors) == 0){
            return TRUE;
        } else {
            return FALSE;
        }
    }
    
    // Checks for logged in user and redirects to login if not found with "page=protected" indicator in URL.
    public function protectPage(&$errors, $isAdmin = FALSE) {
        
        // Get the user ID from the session record
        $user = $this->getSessionUser($errors);
        
        if ($user == NULL) {
            // Redirect the user to the login page
            $this->auditlog("protect page", "no user");
            header("Location: login.php?page=protected");
            exit();
        }
        
        // Get the user's ID
        $userid = $user["userid"];
        
        // If there is no user ID in the session, then the user is not logged in
        if(empty($userid)) {
            
            // Redirect the user to the login page
            $this->auditlog("protect page error", $user);
            header("Location: login.php?page=protected");
            exit();
            
        } else if ($isAdmin)  {
            
            // Get the isAdmin flag from the database
            $isAdminDB = $this->isAdmin($errors, $userid);
            
            if (!$isAdminDB) {
                
                // Redirect the user to the home page
                $this->auditlog("protect page", "not admin");
                header("Location: index.php?page=protectedAdmin");
                exit();
                
            }
            
        }
        
    }
    
    // Get a list of things from the database and will return the $errors array listing any errors encountered
    public function getThings(&$errors) {
        
        // Assume an empty list of things
        $data = array();
        $thingname = "";
        $thingid = "";
        
        // Connect to the database
               if (sizeof($errors) == 0) {
            
			$url = "https://2rnhwtr7e6.execute-api.us-east-2.amazonaws.com/default/getThings";
			$data = array(
				'thingname'=>$thingname,
				'thingid'=>$thingid
			);
			$data_json = json_encode($data);

			$ch = curl_init();
			curl_setopt($ch, CURLOPT_URL, $url);
			curl_setopt($ch, CURLOPT_HTTPHEADER, array('x-api-key:3tEg1MXoeo4K4Q7mtVVuW1quD30CmHSw6BQB3hSY','Content-Type: application/json','Content-Length: ' . strlen($data_json)));
			curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'GET');
			curl_setopt($ch, CURLOPT_POSTFIELDS, $data_json);
			curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
			$response  = curl_exec($ch);
			$httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);

			if ($response === FALSE) {
				$errors[] = "An unexpected failure occurred contacting the web service.";
			} else {

				if($httpCode == 400) {
					
					// JSON was double-encoded, so it needs to be double decoded
					$errorsList = json_decode(json_decode($response))->errors;
					foreach ($errorsList as $err) {
						$errors[] = $err;
					}
					if (sizeof($errors) == 0) {
						$errors[] = "Bad input";
					}

				} else if($httpCode == 500) {

					$errorsList = json_decode(json_decode($response))->errors;
					foreach ($errorsList as $err) {
						$errors[] = $err;
					}
					if (sizeof($errors) == 0) {
						$errors[] = "Server error";
					}

				} else if($httpCode == 200) {

					$this->getThings(&$errors);

				}

			}
			
			curl_close($ch);

        } else {
            $this->auditlog("fetching things error", $errors);
        }
        
        // Return TRUE if there are no errors, otherwise return FALSE
        if (sizeof($errors) == 0){
            return TRUE;
        } else {
            return FALSE;
        }
    // Return the list of things
        return $data;
    }
    
    // Get a single thing from the database and will return the $errors array listing any errors encountered
    public function getThing($thingid, &$errors) {
        
        // Assume no thing exists for this thing id
        $thing = NULL;
        
        // Check for a valid thing ID
        if (empty($thingid)){
            $errors[] = "Missing thing ID";
        }
        
    if (sizeof($errors) == 0) {

			$url = "https://2rnhwtr7e6.execute-api.us-east-2.amazonaws.com/default/getThing";
			$data = array(
				'thingid'=>$uthingid
			);
			$data_json = json_encode($data);

			$ch = curl_init();
			curl_setopt($ch, CURLOPT_URL, $url);
			curl_setopt($ch, CURLOPT_HTTPHEADER, array('x-api-key:3tEg1MXoeo4K4Q7mtVVuW1quD30CmHSw6BQB3hSY','Content-Type: application/json','Content-Length: ' . strlen($data_json)));
			curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'GET');
			curl_setopt($ch, CURLOPT_POSTFIELDS, $data_json);
			curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
			$response  = curl_exec($ch);
			$httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);

			if ($response === FALSE) {
				$errors[] = "An unexpected failure occurred contacting the web service.";
			} else {

				if($httpCode == 400) {
					
					// JSON was double-encoded, so it needs to be double decoded
					$errorsList = json_decode(json_decode($response))->errors;
					foreach ($errorsList as $err) {
						$errors[] = $err;
					}
					if (sizeof($errors) == 0) {
						$errors[] = "Bad input";
					}

				} else if($httpCode == 500) {

					$errorsList = json_decode(json_decode($response))->errors;
					foreach ($errorsList as $err) {
						$errors[] = $err;
					}
					if (sizeof($errors) == 0) {
						$errors[] = "Server error";
					}

				} else if($httpCode == 200) {

					$this->getThing($thingid, &$errors);

				}

			}
			
			curl_close($ch);

        } else {
            $this->auditlog("fetching thing error", $errors);
        }
        
        // Return TRUE if there are no errors, otherwise return FALSE
        if (sizeof($errors) == 0){
            return TRUE;
        } else {
            return FALSE;
        }
    // Return the thing
        return $thing;
    }
    
    // Get a list of comments from the database
    public function getComments($thingid, &$errors) {
        
        // Assume an empty list of comments
        $comments = array();
      
        // Check for a valid thing ID
        if (empty($thingid)) {
            
            // Add an appropriate error message to the list
            $errors[] = "Missing thing ID";
            $this->auditlog("getComments validation error", $errors);
            
        } else {
             $url = "https://2rnhwtr7e6.execute-api.us-east-2.amazonaws.com/default/getComments";
			$comments = array(
				'thingid'=>$thingid
			);
			$data_json = json_encode($comments);

			$ch = curl_init();
			curl_setopt($ch, CURLOPT_URL, $url);
			curl_setopt($ch, CURLOPT_HTTPHEADER, array('x-api-key:3tEg1MXoeo4K4Q7mtVVuW1quD30CmHSw6BQB3hSY','Content-Type: application/json','Content-Length: ' . strlen($data_json)));
			curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'GET');
			curl_setopt($ch, CURLOPT_POSTFIELDS, $data_json);
			curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
			$response  = curl_exec($ch);
			$httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);

			if ($response === FALSE) {
				$errors[] = "An unexpected failure occurred contacting the web service.";
			} else {

				if($httpCode == 400) {
					
					// JSON was double-encoded, so it needs to be double decoded
					$errorsList = json_decode(json_decode($response))->errors;
					foreach ($errorsList as $err) {
						$errors[] = $err;
					}
					if (sizeof($errors) == 0) {
						$errors[] = "Bad input";
					}

				} else if($httpCode == 500) {

					$errorsList = json_decode(json_decode($response))->errors;
					foreach ($errorsList as $err) {
						$errors[] = $err;
					}
					if (sizeof($errors) == 0) {
						$errors[] = "Server error";
					}

				} else if($httpCode == 200) {

					$this->getComments($thingid, &$errors);

				}

			}
			
			curl_close($ch);

        } else {
            $this->auditlog("comment retrieval error", $errors);
        }
        
         // Return the list of comments
        return $comments;
           
           
        }
    
    // Handles the saving of uploaded attachments and the creation of a corresponding record in the attachments table.
    public function saveAttachment($dbh, $attachment, &$errors) {
        
        $attachmentid = NULL;
        
        // Check for an attachment
        if (isset($attachment) && isset($attachment['name']) && !empty($attachment['name'])) {
            
            // Get the list of valid attachment types and file extensions
            $attachmenttypes = $this->getAttachmentTypes($errors);
            
            // Construct an array containing only the 'extension' keys
            $extensions = array_column($attachmenttypes, 'extension');
            
            // Get the uploaded filename
            $filename = $attachment['name'];
            
            // Extract the uploaded file's extension
            $dot = strrpos($filename, ".");
            
            // Make sure the file has an extension and the last character of the name is not a "."
            if ($dot !== FALSE && $dot != strlen($filename)) {
                
                // Check to see if the uploaded file has an allowed file extension
                $extension = strtolower(substr($filename, $dot + 1));
                if (!in_array($extension, $extensions)) {
                    
                    // Not a valid file extension
                    $errors[] = "File does not have a valid file extension";
                    $this->auditlog("saveAttachment", "invalid file extension: $filename");
                    
                }
                
            } else {
                
                // No file extension -- Disallow
                $errors[] = "File does not have a valid file extension";
                $this->auditlog("saveAttachment", "no file extension: $filename");
                
            }
            
            // Only attempt to add the attachment to the database if the file extension was good
            if (sizeof($errors) == 0) {
                
                // Create a new ID
                $attachmentid = bin2hex(random_bytes(16));
                
                 // Hash the user's password
            $passwordhash = password_hash($password, PASSWORD_DEFAULT);
            
            // Create a new user ID
            $userid = bin2hex(random_bytes(16));

			$url = "https://2rnhwtr7e6.execute-api.us-east-2.amazonaws.com/default/saveAttachment";
			$data = array(
				'userid'=>$userid,
				'attachmentid'=>$attachmentid,
				'extension'=>$extensions,
				'filename'=>$dot
			);
			$data_json = json_encode($data);

			$ch = curl_init();
			curl_setopt($ch, CURLOPT_URL, $url);
			curl_setopt($ch, CURLOPT_HTTPHEADER, array('x-api-key:3tEg1MXoeo4K4Q7mtVVuW1quD30CmHSw6BQB3hSY','Content-Type: application/json','Content-Length: ' . strlen($data_json)));
			curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'POST');
			curl_setopt($ch, CURLOPT_POSTFIELDS, $data_json);
			curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
			$response  = curl_exec($ch);
			$httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);

			if ($response === FALSE) {
				$errors[] = "An unexpected failure occurred contacting the web service.";
			} else {

				if($httpCode == 400) {
					
					// JSON was double-encoded, so it needs to be double decoded
					$errorsList = json_decode(json_decode($response))->errors;
					foreach ($errorsList as $err) {
						$errors[] = $err;
					}
					if (sizeof($errors) == 0) {
						$errors[] = "Bad input";
					}

				} else if($httpCode == 500) {

					$errorsList = json_decode(json_decode($response))->errors;
					foreach ($errorsList as $err) {
						$errors[] = $err;
					}
					if (sizeof($errors) == 0) {
						$errors[] = "Server error";
					}

				} else if($httpCode == 200) {

					$this->saveAttachment($dbh, $attachment, &$errors);

				}

			}
			
			curl_close($ch);

        } else {
            $this->auditlog("save attachment error", $errors);
                 // Move the file from temp folder to html attachments folder
                    move_uploaded_file($attachment['tmp_name'], getcwd() . '/attachments/' . $attachmentid . '-' . $attachment['name']);
                    $attachmentname = $attachment["name"];
                    $this->auditlog("saveAttachment", "success: $attachmentname");
        }
		
   }
   return $attachmentid;
}
    
    
    // Adds a new thing to the database
    public function addThing($name, $attachment, &$errors) {
        
        // Get the user id from the session
        $user = $this->getSessionUser($errors);
        $userid = $user["userid"];
        $registrationcode = $user["registrationcode"];
        
        // Validate the user input
        if (empty($userid)) {
            $errors[] = "Missing user ID. Not logged in?";
        }
        if (empty($name)) {
            $errors[] = "Missing thing name";
        }
        
           if (sizeof($errors) == 0) {
            $url = "https://2rnhwtr7e6.execute-api.us-east-2.amazonaws.com/default/addThinf";
			$data = array(
				'userid'=>$userid,
				'user'=>$user,
				'name'=>$name,
				'attachment'=>$attachment
			);
			$data_json = json_encode($data);

			$ch = curl_init();
			curl_setopt($ch, CURLOPT_URL, $url);
			curl_setopt($ch, CURLOPT_HTTPHEADER, array('x-api-key:3tEg1MXoeo4K4Q7mtVVuW1quD30CmHSw6BQB3hSY','Content-Type: application/json','Content-Length: ' . strlen($data_json)));
			curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'POST');
			curl_setopt($ch, CURLOPT_POSTFIELDS, $data_json);
			curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
			$response  = curl_exec($ch);
			$httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);

			if ($response === FALSE) {
				$errors[] = "An unexpected failure occurred contacting the web service.";
			} else {

				if($httpCode == 400) {
					
					// JSON was double-encoded, so it needs to be double decoded
					$errorsList = json_decode(json_decode($response))->errors;
					foreach ($errorsList as $err) {
						$errors[] = $err;
					}
					if (sizeof($errors) == 0) {
						$errors[] = "Bad input";
					}

				} else if($httpCode == 500) {

					$errorsList = json_decode(json_decode($response))->errors;
					foreach ($errorsList as $err) {
						$errors[] = $err;
					}
					if (sizeof($errors) == 0) {
						$errors[] = "Server error";
					}

				} else if($httpCode == 200) {

					$this->addThing($name, $attachment, &$errors);

				}

			}
			
			curl_close($ch);

        } else {
            $this->auditlog("error adding thing", $errors);
        }
        
        // Return TRUE if there are no errors, otherwise return FALSE
        if (sizeof($errors) == 0){
            return TRUE;
        } else {
            return FALSE;
        }
    }
    
    // Adds a new comment to the database
    public function addComment($text, $thingid, $attachment, &$errors) {
        
        // Get the user id from the session
        $user = $this->getSessionUser($errors);
        $userid = $user["userid"];
        
        // Validate the user input
        if (empty($userid)) {
            $errors[] = "Missing user ID. Not logged in?";
        }
        if (empty($thingid)) {
            $errors[] = "Missing thing ID";
        }
        if (empty($text)) {
            $errors[] = "Missing comment text";
        }
        
        // Only try to insert the data into the database if there are no validation errors
        if (sizeof($errors) == 0) {
           $url = "https://2rnhwtr7e6.execute-api.us-east-2.amazonaws.com/default/addComment";
			$data = array(
				'thingid'=>$thingid,
				'commenttext'=>$text,
				'userid'=>$userid,
				'attachment'=>$attachment
			);
			$data_json = json_encode($data);

			$ch = curl_init();
			curl_setopt($ch, CURLOPT_URL, $url);
			curl_setopt($ch, CURLOPT_HTTPHEADER, array('x-api-key:3tEg1MXoeo4K4Q7mtVVuW1quD30CmHSw6BQB3hSY','Content-Type: application/json','Content-Length: ' . strlen($data_json)));
			curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'POST');
			curl_setopt($ch, CURLOPT_POSTFIELDS, $data_json);
			curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
			$response  = curl_exec($ch);
			$httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);

			if ($response === FALSE) {
				$errors[] = "An unexpected failure occurred contacting the web service.";
			} else {

				if($httpCode == 400) {
					
					// JSON was double-encoded, so it needs to be double decoded
					$errorsList = json_decode(json_decode($response))->errors;
					foreach ($errorsList as $err) {
						$errors[] = $err;
					}
					if (sizeof($errors) == 0) {
						$errors[] = "Bad input";
					}

				} else if($httpCode == 500) {

					$errorsList = json_decode(json_decode($response))->errors;
					foreach ($errorsList as $err) {
						$errors[] = $err;
					}
					if (sizeof($errors) == 0) {
						$errors[] = "Server error";
					}

				} else if($httpCode == 200) {

					$this->addComment($text, $thingid, $attachment, &$errors);

				}

			}
			
			curl_close($ch);

        } else {
            $this->auditlog("add comment error", $errors);
        }
        
        // Return TRUE if there are no errors, otherwise return FALSE
        if (sizeof($errors) == 0){
            return TRUE;
        } else {
            return FALSE;
        }
    }
    
    // Get a list of users from the database and will return the $errors array listing any errors encountered
    public function getUsers(&$errors) {
        
        // Assume an empty list of topics
        $users = array();
         $userid = "";
         $username = "";
         
        if (sizeof($errors) == 0) {
     $url = "https://2rnhwtr7e6.execute-api.us-east-2.amazonaws.com/default/getUsers";
			$users = array(
				'userid'=>$userid,
                'username'=>$username
			);
			$data_json = json_encode($users);

			$ch = curl_init();
			curl_setopt($ch, CURLOPT_URL, $url);
			curl_setopt($ch, CURLOPT_HTTPHEADER, array('x-api-key:3tEg1MXoeo4K4Q7mtVVuW1quD30CmHSw6BQB3hSY','Content-Type: application/json','Content-Length: ' . strlen($data_json)));
			curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'GET');
			curl_setopt($ch, CURLOPT_POSTFIELDS, $data_json);
			curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
			$response  = curl_exec($ch);
			$httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);

			if ($response === FALSE) {
				$errors[] = "An unexpected failure occurred contacting the web service.";
			} else {

				if($httpCode == 400) {
					
					// JSON was double-encoded, so it needs to be double decoded
					$errorsList = json_decode(json_decode($response))->errors;
					foreach ($errorsList as $err) {
						$errors[] = $err;
					}
					if (sizeof($errors) == 0) {
						$errors[] = "Bad input";
					}

				} else if($httpCode == 500) {

					$errorsList = json_decode(json_decode($response))->errors;
					foreach ($errorsList as $err) {
						$errors[] = $err;
					}
					if (sizeof($errors) == 0) {
						$errors[] = "Server error";
					}

				} else if($httpCode == 200) {

					$this->getUsers(&$errors);

				}

			}
			
			curl_close($ch);
            
        }else{
        
         $this->auditlog("getting users error", $errors);
    }
     // Return the list of users
        return $users;
 }
    
    // Gets a single user from database and will return the $errors array listing any errors encountered
    public function getUser($userid, &$errors) {
        
        // Assume no user exists for this user id
        $user = NULL;
        
        // Validate the user input
        if (empty($userid)) {
            $errors[] = "Missing userid";
        }
        
               if (sizeof($errors) == 0) {
            $url = "https://2rnhwtr7e6.execute-api.us-east-2.amazonaws.com/default/getUser";
			$data = array(
				'userid'=>$userid
			);
			$data_json = json_encode($data);

			$ch = curl_init();
			curl_setopt($ch, CURLOPT_URL, $url);
			curl_setopt($ch, CURLOPT_HTTPHEADER, array('x-api-key:3tEg1MXoeo4K4Q7mtVVuW1quD30CmHSw6BQB3hSY','Content-Type: application/json','Content-Length: ' . strlen($data_json)));
			curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'GET');
			curl_setopt($ch, CURLOPT_POSTFIELDS, $data_json);
			curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
			$response  = curl_exec($ch);
			$httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);

			if ($response === FALSE) {
				$errors[] = "An unexpected failure occurred contacting the web service.";
			} else {

				if($httpCode == 400) {
					
					// JSON was double-encoded, so it needs to be double decoded
					$errorsList = json_decode(json_decode($response))->errors;
					foreach ($errorsList as $err) {
						$errors[] = $err;
					}
					if (sizeof($errors) == 0) {
						$errors[] = "Bad input";
					}

				} else if($httpCode == 500) {

					$errorsList = json_decode(json_decode($response))->errors;
					foreach ($errorsList as $err) {
						$errors[] = $err;
					}
					if (sizeof($errors) == 0) {
						$errors[] = "Server error";
					}

				} else if($httpCode == 200) {

					$this->getUser($userid, &$errors);

				}

			}
			
			curl_close($ch);

        } else {
            $this->auditlog("error getting user", $errors);
        }
        
        // Return user if there are no errors, otherwise return NULL
        return $user;
    }
    
    
    // Updates a single user in the database and will return the $errors array listing any errors encountered
    public function updateUser($userid, $username, $email, $password, $isadminDB, &$errors) {
        
        // Assume no user exists for this user id
        $user = NULL;
        
        // Validate the user input
        if (empty($userid)) {
            $errors[] = "Missing userid";
        }
        
         if (sizeof($errors) == 0) {
           $url = "https://2rnhwtr7e6.execute-api.us-east-2.amazonaws.com/default/updateUser";
			$data = array(
				'userid'=>$userid,
				'username'=>$username,
				'password'=>$password,
				'email'=>$email,
				'isadmin'=>$isadmindb
			);
			$data_json = json_encode($data);

			$ch = curl_init();
			curl_setopt($ch, CURLOPT_URL, $url);
			curl_setopt($ch, CURLOPT_HTTPHEADER, array('x-api-key:3tEg1MXoeo4K4Q7mtVVuW1quD30CmHSw6BQB3hSY','Content-Type: application/json','Content-Length: ' . strlen($data_json)));
			curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'POST');
			curl_setopt($ch, CURLOPT_POSTFIELDS, $data_json);
			curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
			$response  = curl_exec($ch);
			$httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);

			if ($response === FALSE) {
				$errors[] = "An unexpected failure occurred contacting the web service.";
			} else {

				if($httpCode == 400) {
					
					// JSON was double-encoded, so it needs to be double decoded
					$errorsList = json_decode(json_decode($response))->errors;
					foreach ($errorsList as $err) {
						$errors[] = $err;
					}
					if (sizeof($errors) == 0) {
						$errors[] = "Bad input";
					}

				} else if($httpCode == 500) {

					$errorsList = json_decode(json_decode($response))->errors;
					foreach ($errorsList as $err) {
						$errors[] = $err;
					}
					if (sizeof($errors) == 0) {
						$errors[] = "Server error";
					}

				} else if($httpCode == 200) {

					$this->updateUser($userid, $username, $email, $password, $isadminDB, &$errors);

				}

			}
			
			curl_close($ch);

        } else {
            $this->auditlog("update user error", $errors);
        }
        
        // Return TRUE if there are no errors, otherwise return FALSE
        if (sizeof($errors) == 0){
            return TRUE;
        } else {
            return FALSE;
        }
    }
    
    // Validates a provided username or email address and sends a password reset email
    public function passwordReset($usernameOrEmail, &$errors) {
        
        // Check for a valid username/email
        if (empty($usernameOrEmail)) {
            $errors[] = "Missing username/email";
            $this->auditlog("session", "missing username");
        }
        
        // Only proceed if there are no validation errors
       if (sizeof($errors) == 0) {
           $url = "https://2rnhwtr7e6.execute-api.us-east-2.amazonaws.com/default/passwordReset";
			$data = array(
				'username'=>$usernameOrEmail,
				'email'=>$usernameOrEmail
			);
			$data_json = json_encode($data);

			$ch = curl_init();
			curl_setopt($ch, CURLOPT_URL, $url);
			curl_setopt($ch, CURLOPT_HTTPHEADER, array('x-api-key:3tEg1MXoeo4K4Q7mtVVuW1quD30CmHSw6BQB3hSY','Content-Type: application/json','Content-Length: ' . strlen($data_json)));
			curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'PUT');
			curl_setopt($ch, CURLOPT_POSTFIELDS, $data_json);
			curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
			$response  = curl_exec($ch);
			$httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);

			if ($response === FALSE) {
				$errors[] = "An unexpected failure occurred contacting the web service.";
			} else {

				if($httpCode == 400) {
					
					// JSON was double-encoded, so it needs to be double decoded
					$errorsList = json_decode(json_decode($response))->errors;
					foreach ($errorsList as $err) {
						$errors[] = $err;
					}
					if (sizeof($errors) == 0) {
						$errors[] = "Bad input";
					}

				} else if($httpCode == 500) {

					$errorsList = json_decode(json_decode($response))->errors;
					foreach ($errorsList as $err) {
						$errors[] = $err;
					}
					if (sizeof($errors) == 0) {
						$errors[] = "Server error";
					}

				} else if($httpCode == 200) {

					$this->passwordReset($usernameOrEmail, &$errors);
                    $this->auditlog("passwordReset", "Sending message to $email");
                    
                    // Send reset email
                    $pageLink = (isset($_SERVER['HTTPS']) ? "https" : "http") . "://$_SERVER[HTTP_HOST]$_SERVER[REQUEST_URI]";
                    $pageLink = str_replace("reset.php", "password.php", $pageLink);
                    $to      = $email;
                    $subject = 'Password reset';
                    $message = "A password reset request for this account has been submitted at https://anguthrie.me. ".
                        "If you did not make this request, please ignore this message. No other action is necessary. ".
                        "To reset your password, please click the following link: $pageLink?id=$passwordresetid";
                    $headers = 'From: webmaster@anguthrie.me' . "\r\n" .
                        'Reply-To: webmaster@anguthrie.me' . "\r\n";
                    
                    mail($to, $subject, $message, $headers);
                
				}

			}
			
			curl_close($ch);

        } else {
            $this->auditlog("passwordReset", "Bad request for $usernameOrEmail");
        }
          
}
    
    // Validates a provided username or email address and sends a password reset email
 public function updatePassword($password, $passwordresetid, &$errors) {
        
        // Check for a valid username/email
        $this->validatePassword($password, $errors);
        if (empty($passwordresetid)) {
            $errors[] = "Missing passwordresetid";
        }
        
        // Only proceed if there are no validation errors
              if (sizeof($errors) == 0) {
                  
                  // Hash the user's password
            $passwordHash = password_hash($password, PASSWORD_DEFAULT);
                  
           $url = "https://2rnhwtr7e6.execute-api.us-east-2.amazonaws.com/default/updatePassword";
			$data = array(
				'passwordHash'=>$passwordHash,
				'passwordresetid'=>$passwordresetid
			);
			$data_json = json_encode($data);

			$ch = curl_init();
			curl_setopt($ch, CURLOPT_URL, $url);
			curl_setopt($ch, CURLOPT_HTTPHEADER, array('x-api-key:3tEg1MXoeo4K4Q7mtVVuW1quD30CmHSw6BQB3hSY','Content-Type: application/json','Content-Length: ' . strlen($data_json)));
			curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'PUT');
			curl_setopt($ch, CURLOPT_POSTFIELDS, $data_json);
			curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
			$response  = curl_exec($ch);
			$httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);

			if ($response === FALSE) {
				$errors[] = "An unexpected failure occurred contacting the web service.";
			} else {

				if($httpCode == 400) {
					
					// JSON was double-encoded, so it needs to be double decoded
					$errorsList = json_decode(json_decode($response))->errors;
					foreach ($errorsList as $err) {
						$errors[] = $err;
					}
					if (sizeof($errors) == 0) {
						$errors[] = "Bad input";
					}

				} else if($httpCode == 500) {

					$errorsList = json_decode(json_decode($response))->errors;
					foreach ($errorsList as $err) {
						$errors[] = $err;
					}
					if (sizeof($errors) == 0) {
						$errors[] = "Server error";
					}

				} else if($httpCode == 200) {

					$this-> updatePassword($password, $passwordresetid, &$errors);

				}

			}
			
			curl_close($ch);
         
            } else {
                
                $this->auditlog("updatePassword", "Bad request id: $passwordresetid");
                
            }
            
        }
    
    function getFile($name){
        return file_get_contents($name);
    }
    
    // Get a list of users from the database and will return the $errors array listing any errors encountered
    public function getAttachmentTypes(&$errors) {
        
        // Assume an empty list of topics
        $types = array();
        $attachmenttypeid="";
        $name="";
        $extension="";
        
        if (sizeof($errors) == 0) {
            $url = "https://2rnhwtr7e6.execute-api.us-east-2.amazonaws.com/default/getAttachmentTypes";
			$types = array(
				'attachmenttypeid'=>$userid,
				'name'=>$name,
				'extentsion'=>$extension
			);
			$data_json = json_encode($types);

			$ch = curl_init();
			curl_setopt($ch, CURLOPT_URL, $url);
			curl_setopt($ch, CURLOPT_HTTPHEADER, array('x-api-key:3tEg1MXoeo4K4Q7mtVVuW1quD30CmHSw6BQB3hSY','Content-Type: application/json','Content-Length: ' . strlen($data_json)));
			curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'GET');
			curl_setopt($ch, CURLOPT_POSTFIELDS, $data_json);
			curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
			$response  = curl_exec($ch);
			$httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);

			if ($response === FALSE) {
				$errors[] = "An unexpected failure occurred contacting the web service.";
			} else {

				if($httpCode == 400) {
					
					// JSON was double-encoded, so it needs to be double decoded
					$errorsList = json_decode(json_decode($response))->errors;
					foreach ($errorsList as $err) {
						$errors[] = $err;
					}
					if (sizeof($errors) == 0) {
						$errors[] = "Bad input";
					}

				} else if($httpCode == 500) {

					$errorsList = json_decode(json_decode($response))->errors;
					foreach ($errorsList as $err) {
						$errors[] = $err;
					}
					if (sizeof($errors) == 0) {
						$errors[] = "Server error";
					}

				} else if($httpCode == 200) {

					$this->getAttachmentTypes(&$errors);

				}

			}
			
			curl_close($ch);

        } else {
            $this->auditlog("get attachment type error", $errors);
        }
 
        // Return the list of users
        return $types;
        
    }
    
    // Creates a new session in the database for the specified user
    public function newAttachmentType($name, $extension, &$errors) {
        
        $attachmenttypeid = NULL;
        
        // Check for a valid name
        if (empty($name)) {
            $errors[] = "Missing name";
        }
        // Check for a valid extension
        if (empty($extension)) {
            $errors[] = "Missing extension";
        }
        
        // Only try to query the data into the database if there are no validation errors
      if (sizeof($errors) == 0) {
           $url = "https://2rnhwtr7e6.execute-api.us-east-2.amazonaws.com/default/newAttachmentType";
			$data = array(
				'name'=>$name,
				'extension'=>$extension,
                'attachmentypeid'=>$attachmenttypeid
			);
			$data_json = json_encode($data);

			$ch = curl_init();
			curl_setopt($ch, CURLOPT_URL, $url);
			curl_setopt($ch, CURLOPT_HTTPHEADER, array('x-api-key:3tEg1MXoeo4K4Q7mtVVuW1quD30CmHSw6BQB3hSY','Content-Type: application/json','Content-Length: ' . strlen($data_json)));
			curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'POST');
			curl_setopt($ch, CURLOPT_POSTFIELDS, $data_json);
			curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
			$response  = curl_exec($ch);
			$httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);

			if ($response === FALSE) {
				$errors[] = "An unexpected failure occurred contacting the web service.";
			} else {

				if($httpCode == 400) {
					
					// JSON was double-encoded, so it needs to be double decoded
					$errorsList = json_decode(json_decode($response))->errors;
					foreach ($errorsList as $err) {
						$errors[] = $err;
					}
					if (sizeof($errors) == 0) {
						$errors[] = "Bad input";
					}

				} else if($httpCode == 500) {

					$errorsList = json_decode(json_decode($response))->errors;
					foreach ($errorsList as $err) {
						$errors[] = $err;
					}
					if (sizeof($errors) == 0) {
						$errors[] = "Server error";
					}

				} else if($httpCode == 200) {

					$this->newAttachmentType($name, $extension, &$errors);
				}

			}
			
			curl_close($ch);
            
        } else {
            
            $this->auditlog("newAttachmentType error", $errors);
            return NULL;
            
        }
        
        return $attachmenttypeid;
    }
  
function sendOtpEmail($userid, $email, &$errors) {
        
        // Connect to the database
        $dbh = $this->getConnection();
        
        $this->auditlog("sendOtpEmail", "Sending message to $email");
        
        $otp = bin2hex(random_bytes(3));
        
        // Construct a SQL statement to perform the insert operation
        $sql = "INSERT INTO otpvalidation (otp, userid, email, emailsent) " .
            "VALUES (:otp, :userid, :email, NOW())";
        
        // Run the SQL select and capture the result code
        $stmt = $dbh->prepare($sql);
        $stmt->bindParam(":otp", $otp);
        $stmt->bindParam(":userid", $userid);
        $stmt->bindParam(":email", $email);
        $result = $stmt->execute();
        if ($result === FALSE) {
            $errors[] = "An unexpected error occurred sending the validation email";
            $this->debug($stmt->errorInfo());
            $this->auditlog("register error", $stmt->errorInfo());
        } else {
            
            $this->auditlog("sendOtpEmail", "Sending message to $email");
            
            // Send reset email
            $pageLink = (isset($_SERVER['HTTPS']) ? "https" : "http") . "://$_SERVER[HTTP_HOST]$_SERVER[REQUEST_URI]";
            $pageLink = str_replace("login.php", "otp.php", $pageLink);
            $to      = $email;
            $subject = 'Your One Time Password';
            $message = "Your one time password is $otp";
            $headers = 'From: webmaster@anguthrie.me' . "\r\n" .
                'Reply-To: webmaster@anguthrie.me' . "\r\n";
            
            mail($to, $subject, $message, $headers);
            
            $this->auditlog("sendOtpEmail", "Message sent to $email");
            
        }
        
        // Close the connection
        $dbh = NULL;
        
    }

function processOtp($otp, &$errors) {
        
        $success = FALSE;
        
        // Connect to the database
        $dbh = $this->getConnection();
        
        $this->auditlog("processOtp", "Received: $otp");
        
        // Construct a SQL statement to perform the insert operation
        $sql = "SELECT userid FROM otpvalidation WHERE otp = :otp";
        
        // Run the SQL select and capture the result code
        $stmt = $dbh->prepare($sql);
        $stmt->bindParam(":otp", $otp);
        $result = $stmt->execute();
        
        if ($result === FALSE) {
            
            $errors[] = "An unexpected error occurred processing your email validation request";
            $this->debug($stmt->errorInfo());
            $this->auditlog("processOtp error", $stmt->errorInfo());
            
        } else {
            
            if ($stmt->rowCount() != 1) {
                
                $errors[] = "That does not appear to be a valid request";
                $this->debug($stmt->errorInfo());
                $this->auditlog("processOtp", "Invalid request: $otp");
                
                
            } else {
                
                $userid = $stmt->fetch(PDO::FETCH_ASSOC)['userid'];
                
                // Construct a SQL statement to perform the insert operation
                $sql = "DELETE FROM otpvalidation WHERE otp = :otp";
                
                // Run the SQL select and capture the result code
                $stmt = $dbh->prepare($sql);
                $stmt->bindParam(":otp", $otp);
                $result = $stmt->execute();
                
                if ($result === FALSE) {
                    
                    $errors[] = "An unexpected error occurred processing your email validation request";
                    $this->debug($stmt->errorInfo());
                    $this->auditlog("processOtp error", $stmt->errorInfo());
                    
                } else if ($stmt->rowCount() == 1) {
                    
                    $this->auditlog("processOtp", "Email address validated: $otp");
                    
                  $this->newSession($userid);                    
                    $success = TRUE;
                    
                } else {
                    
                    $errors[] = "That does not appear to be a valid request";
                    $this->debug($stmt->errorInfo());
                    $this->auditlog("processOtp", "Invalid request: $otp");
                    
                }
                
            }
            
        }
        
        
        // Close the connection
        $dbh = NULL;
        
        return $success;
        
    }
  
}



?>