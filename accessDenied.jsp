<!DOCTYPE html>
<html>
<head>
    <title>
        Authentication
    </title>
    <!-- Latest compiled and minified CSS -->
    <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/css/bootstrap.min.css" integrity="sha384-BVYiiSIFeK1dGmJRAkycuHAHRg32OmUcww7on3RYdg4Va+PmSTsz/K68vbdEjh4u" crossorigin="anonymous">

    <script src="https://code.jquery.com/jquery-3.2.1.min.js" crossorigin="anonymous"></script>

    <!-- Latest compiled and minified JavaScript -->
    <script src="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/js/bootstrap.min.js" integrity="sha384-Tc5IQib027qvyjSMfHjOMaLkfuWVxZxUPnCJA7l2mCWNIpG9mGCD8wGNIcPD7Txa" crossorigin="anonymous"></script>
</head>
<body>
<h3 class="text-center">Authentication</h3>
<div class="container">
    <form>
        <div class="form-group">
            <label for="username">Username</label>
            <input type="text" class="form-control" id="username" placeholder="Username">
        </div>
        <div class="form-group">
            <label for="password">Password</label>
            <input type="password" class="form-control" id="password" placeholder="Password">
        </div>
        <button type="button" class="btn btn-primary center-block" onclick="auth()">Submit</button>
    </form>
    <div id="token-display">
    </div>
</div>
</br>
</br>

<script type="text/javascript">
    auth= function(){
        var xhttp = new XMLHttpRequest();
        data={name:document.getElementById("username").value,password:document.getElementById("password").value}
        xhttp.onreadystatechange = function() {
            if (xhttp.readyState==4) {
                var response = xhttp.responseText;
                document.getElementById("token-display").innerHTML = response;
            }
        };
        xhttp.open("POST", "http://localhost:8080/auth", true);
        xhttp.setRequestHeader("Content-type", 'application/json; charset=UTF-8');
        xhttp.send(JSON.stringify(data));
    }

</script>
</body>
</html>