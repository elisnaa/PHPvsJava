<!--
# Sample information

Patterns:
- Source: filter_input_array_prm__<c>(INPUT_GET)_<array>(<ae_k>(<s>(t),<c>(FILTER_SANITIZE_SPECIAL_CHARS))) ==> Filters:[Filtered(", &, ', <, >)]
- Sanitization: str_getcsv_prm_ ==> Filters:[Filtered(,)]
- Filters complete: Filters:[Filtered(", &, ', <, ,, >)]
- Dataflow: assignment
- Context: sql_apostrophe
- Sink: db2_exec_prm__<$>(db)

State:
- State: Good
- Exploitable: Not found


# Exploit description

-->
<?php
# Init
$dsn = "DATABASE=myDB;HOSTNAME=ibm_db2;PORT=50000;PROTOCOL=TCPIP;UID=db2inst1;PWD=ibm_db2_pw;";
$db = db2_connect($dsn, "", "");


# Sample
$tainted = filter_input_array(INPUT_GET, ["t" => FILTER_SANITIZE_SPECIAL_CHARS]);
$tainted = $tainted["t"];
$sanitized = str_getcsv($tainted);
$sanitized = implode($sanitized, "_");
$dataflow = $sanitized;
$context = (("SELECT * FROM users WHERE password ='" . $dataflow) . "';");
$stmt = db2_exec($db, $context);
if($stmt == false)
{
  die(db2_stmt_errormsg());
}
while(($row = db2_fetch_array($stmt)))
{
  echo(htmlentities(print_r($row, true)));
}

?>