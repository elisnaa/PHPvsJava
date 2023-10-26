<!--
# Sample information

Patterns:
- Source: _COOKIE ==> Filters:[]
- Sanitization: gettype_check_prm__<s>(integer) ==> Filters:[letters, specials]
- Filters complete: Filters:[letters, specials]
- Dataflow: assignment
- Context: sql_plain
- Sink: mysqli_real_query_method_prm__<$>(db)

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
$tainted = $_COOKIE;
$tainted = $tainted["t"];
if(gettype($tainted) == "integer")
{
  $sanitized = $tainted;
  $dataflow = $sanitized;
  $context = (("SELECT * FROM users WHERE pin =" . $dataflow) . ";");
  $db->real_query($context);
  $results = $db->use_result();
  while(($row = $results->fetch_row()))
  {
    echo(htmlentities(print_r($row, true)));
  }
}

?>