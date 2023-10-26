<!--
# Sample information

Patterns:
- Source: filter_input_array_prm__<c>(INPUT_GET)_<array>(<ae_k>(<s>(t),<c>(FILTER_UNSAFE_RAW))) ==> Filters:[]
- Sanitization: html_entity_decode_prm_ ==> Filters:[]
- Filters complete: Filters:[]
- Dataflow: assignment
- Context: sql_quotes
- Sink: sqlsrv_query_prm__<$>(db)

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
$tainted = filter_input_array(INPUT_GET, ["t" => FILTER_UNSAFE_RAW]);
$tainted = $tainted["t"];
$sanitized = html_entity_decode($tainted);
$dataflow = $sanitized;
$context = (("SELECT * FROM users WHERE password =\"" . $dataflow) . "\";");
$result = sqlsrv_query($db, $context);
while(($row = sqlsrv_fetch_object($result)))
{
  echo(htmlentities(print_r($row, true)));
}

?>