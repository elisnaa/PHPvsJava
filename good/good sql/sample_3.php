<!--
# Sample information

Patterns:
- Source: filter_input_prm__<c>(INPUT_GET)_<s>(t)_<c>(FILTER_SANITIZE_ADD_SLASHES) ==> Filters:[Escape[\](", ', \)]
- Sanitization: is_float ==> Filters:[letters, specials]
- Filters complete: Filters:[letters, specials, Escape[\](", ', \)]
- Dataflow: assignment
- Context: sql_plain
- Sink: db2_prepare_prm__<$>(db)

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
$tainted = filter_input(INPUT_GET, "t", FILTER_SANITIZE_ADD_SLASHES);
if(is_float($tainted))
{
  $sanitized = $tainted;
  $dataflow = $sanitized;
  $context = (("SELECT * FROM users WHERE pin =" . $dataflow) . ";");
  $stmt = db2_prepare($db, $context);
  if($stmt == false)
  {
    die(db2_stmt_errormsg());
  }
  $result = db2_execute($stmt, []);
  while(($row = db2_fetch_array($stmt)))
  {
    echo(htmlentities(print_r($row, true)));
  }
}

?>