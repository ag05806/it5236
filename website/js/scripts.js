function doSubmit(e) {
	var saveLocal = document.getElementById("saveLocal").checked;
	var saveSession = document.getElementById("saveSession").checked;
	if (saveLocal) {
		console.log("Saving username to local storage");
		var username = document.getElementById("usernameField").value;
		localStorage.setItem("username",username);
		sessionStorage.removeItem("username");
	} else if (saveSession) {
		console.log("Saving username to session storage");
		var username = document.getElementById("usernameField").value;
		sessionStorage.setItem("username",username);
		localStorage.removeItem("username");
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
	}
	else if (usernameSession) {
		document.getElementById("saveSession").checked = true;
		document.getElementById("usernameField").value = usernameSession;
	} else {
		document.getElementById("noSave").checked = true;
	}
}

// Add event listeners for page load and form submit
window.addEventListener("load", doPageLoad, false)
document.getElementById("usernameForm").addEventListener("submit", doSubmit, false);
