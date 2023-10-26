<!--
# Sample information

Patterns:
- Source: _COOKIE ==> Filters:[]
- Sanitization: strstr_prm__<s>(1) ==> Filters:[]
- Filters complete: Filters:[]
- Dataflow: assignment
- Context: sql_apostrophe
- Sink: pdo_query_prm__<$>(pdo)

State:
- State: Bad
- Exploitable: Yes


# Exploit description

1. Escape the apostrophe with '
2. No enclosure and special chars are allowed -> SQL injection
-->
<?php
# Init
$pdo = new PDO("mysql:host=mysql;port=3306;dbname=myDB", "username", "password");


# Sample
$tainted = $_COOKIE;
$tainted = $tainted["t"];
$sanitized = strstr($tainted, "1");
$dataflow = $sanitized;
$context = (("SELECT * FROM users WHERE password ='" . $dataflow) . "';");
$results = $pdo->query($context);
foreach ($results as $row){
  echo(htmlentities(print_r($row, true)));
}

?>