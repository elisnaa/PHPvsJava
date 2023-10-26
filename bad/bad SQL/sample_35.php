<!--
# Sample information

Patterns:
- Source: filter_input_prm__<c>(INPUT_GET)_<s>(t)_<c>(FILTER_SANITIZE_FULL_SPECIAL_CHARS) ==> Filters:[Filtered(", &, ', <, >)]
- Sanitization: fnmatch_prm__<s>(*)_<i>(0) ==> Filters:[]
- Filters complete: Filters:[Filtered(", &, ', <, >)]
- Dataflow: assignment
- Context: sql_plain
- Sink: db2_exec_prm__<$>(db)

State:
- State: Bad
- Exploitable: Yes


# Exploit description

1. No enclosure and special chars are allowed -> SQL injection
-->
<?php
# Init
$dsn = "DATABASE=myDB;HOSTNAME=ibm_db2;PORT=50000;PROTOCOL=TCPIP;UID=db2inst1;PWD=ibm_db2_pw;";
$db = db2_connect($dsn, "", "");


# Sample
$tainted = filter_input(INPUT_GET, "t", FILTER_SANITIZE_FULL_SPECIAL_CHARS);
if(fnmatch("*", $tainted, 0))
{
  $sanitized = $tainted;
  $dataflow = $sanitized;
  $context = (("SELECT * FROM users WHERE pin =" . $dataflow) . ";");
  $stmt = db2_exec($db, $context);
  if($stmt == false)
  {
    die(db2_stmt_errormsg());
  }
  while(($row = db2_fetch_array($stmt)))
  {
    echo(htmlentities(print_r($row, true)));
  }
}

?>