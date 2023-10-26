<!--
# Sample information

Patterns:
- Source: filter_input_prm__<c>(INPUT_GET)_<s>(t)_<c>(FILTER_UNSAFE_RAW) ==> Filters:[]
- Sanitization: addslashes ==> Filters:[Escape[\](", ', \)]
- Filters complete: Filters:[Escape[\](", ', \)]
- Dataflow: assignment
- Context: sql_apostrophe
- Sink: mysqli_prepare_prm__<$>(db)

State:
- State: Good
- Exploitable: Not found


# Exploit description

-->
<?php
# Init
$servername = "mysql";
$username = "username";
$password = "password";
$dbName = "myDB";
$db = new mysqli($servername, $username, $password, $dbName);


# Sample
$tainted = filter_input(INPUT_GET, "t", FILTER_UNSAFE_RAW);
$sanitized = addslashes($tainted);
$dataflow = $sanitized;
$context = (("SELECT * FROM users WHERE password ='" . $dataflow) . "';");
$stmt = mysqli_prepare($db, $context);
mysqli_stmt_execute($stmt);
$results = mysqli_stmt_get_result($stmt);
while(($row = $results->fetch_row()))
{
  echo(htmlentities(print_r($row, true)));
}

?>