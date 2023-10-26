<!--
# Sample information

Patterns:
- Source: _POST ==> Filters:[]
- Sanitization: is_int ==> Filters:[letters, specials]
- Filters complete: Filters:[letters, specials]
- Dataflow: assignment
- Context: sql_apostrophe
- Sink: mysqli_multi_query_prm__<$>(db)

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
$tainted = $_POST;
$tainted = $tainted["t"];
if(is_int($tainted))
{
  $sanitized = $tainted;
  $dataflow = $sanitized;
  $context = (("SELECT * FROM users WHERE password ='" . $dataflow) . "';");
  mysqli_multi_query($db, $context);
  $results = $db->use_result();
  while(($row = $results->fetch_row()))
  {
    echo(htmlentities(print_r($row, true)));
  }
}

?>