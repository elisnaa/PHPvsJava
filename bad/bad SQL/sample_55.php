<!--
# Sample information

Patterns:
- Source: apache_request_headers ==> Filters:[]
- Sanitization: str_ireplace_prm__<s>(')_<s>() ==> Filters:[Filtered(')]
- Filters complete: Filters:[Filtered(')]
- Dataflow: assignment
- Context: sql_quotes
- Sink: mssql_sqlsrv_prepare_prm__<$>(db)

State:
- State: Bad
- Exploitable: Yes


# Exploit description

1. Escape quotes with "
2. No enclosure and special chars are allowed -> SQL injection
-->
<?php
# Init
$info = ["Database" => "myDB", "UID" => "SA", "PWD" => "Msql12345678!"];
$db = sqlsrv_connect("mssql", $info);
if($db == false)
{
  die(print_r(sqlsrv_errors(), true));
}


# Sample
$tainted = apache_request_headers();
$tainted = $tainted["t"];
$sanitized = str_ireplace("'", "", $tainted);
$dataflow = $sanitized;
$context = (("SELECT * FROM users WHERE password =\"" . $dataflow) . "\";");
$stmt = sqlsrv_prepare($db, $context);
$result = sqlsrv_execute($stmt);
while(($row = sqlsrv_fetch_array($stmt, SQLSRV_FETCH_ASSOC)))
{
  echo(htmlentities(print_r($row, true)));
}

?>