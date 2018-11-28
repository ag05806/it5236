var mysql = require('./node_modules/mysql');
var config = require('./config.json');
var validator = require('./validation.js');

function formatErrorResponse(code, errs) {
	return JSON.stringify({ 
		error  : code,
		errors : errs
	});
}

exports.handler = (event, context, callback) => {
	//instruct the function to return as soon as the callback is invoked
	context.callbackWaitsForEmptyEventLoop = false;

	//validate input
	var errors = new Array();
	
	 // Validate the user input
	validator.validatePasswordHash(event.passwordHash, errors);
	validator.validatePasswordResetId(event.passwordresetid, errors);
	
	if(errors.length > 0) {
		// This should be a "Bad Request" error
		callback(formatErrorResponse('BAD_REQUEST', errors));
	} else {
	
	//getConnection equivalent
	var conn = mysql.createConnection({
		host 	: config.dbhost,
		user 	: config.dbuser,
		password : config.dbpassword,
		database : config.dbname
	});
  //prevent timeout from waiting event loop
	context.callbackWaitsForEmptyEventLoop = false;

	//attempts to connect to the database
	conn.connect(function(err) {
	  	
		if (err)  {
			// This should be a "Internal Server Error" error
			callback(formatErrorResponse('INTERNAL_SERVER_ERROR', [err]));
		};
		console.log("Connected!");
		var sql = "SELECT userid FROM passwordreset WHERE passwordresetid = ? AND expires > NOW()  ";
		
		conn.query(sql, [event.passwordHash], function (err, result) {
		  	if (err) {
				// This should be a "Internal Server Error" error
				callback(formatErrorResponse('INTERNAL_SERVER_ERROR', [err]));
		  	//} else {
		    //	console.log("Registration code count is " + result[0].codecount);
		    //	if (result[0].codecount == 0){
		    //		errors.push("Bad registration code");
			//		callback(formatErrorResponse('BAD_REQUEST', errors));
		    	} else {
					conn.query(sql, [event.passwordHash], function (err, result) {
						if (err) {
							// Check for duplicate values
							if(err.errno == 1062) {
								console.log(err.sqlMessage);
								if(err.sqlMessage.indexOf('passwordHash') != -1) {
									// This should be a "Internal Server Error" error
									callback(formatErrorResponse('BAD_REQUEST', ["Password incorrect"]));
								} else {
                	// This should be a "Internal Server Error" error
									callback(formatErrorResponse('BAD_REQUEST', ["Duplicate value"]));
								}
							} else {
								// This should be a "Internal Server Error" error
								callback(formatErrorResponse('INTERNAL_SERVER_ERROR', [err]));
							}
			      		} else {
				      		var sql = "SELECT userid FROM passwordreset WHERE passwordresetid = ? AND expires > NOW() ";
									conn.query(sql, [event.passwordHash, event.passwordresetid], function (err, result) {
								if (err) {
					        		callback(formatErrorResponse('INTERNAL_SERVER_ERROR', [err]));
					      		} else {
						        	console.log("successful update");
					      			callback(null,"password update successful");
				      			}
		      				}); //query userregistrations
			      		} //error users
		    			}); //query users
		  			} //good registration
			//	} //good code count
		  	}); //query registration codes
		}); //connect database
	} //no validation errors
} //handler
