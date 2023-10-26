<!--
# Sample information

Patterns:
- Source: _REQUEST ==> Filters:[]
- Sanitization: htmlspecialchars_prm__<c>(ENT_COMPAT) ==> Filters:[Filtered(", &, <, >)]
- Filters complete: Filters:[Filtered(", &, <, >)]
- Dataflow: assignment
- Context: sql_apostrophe
- Sink: sqlite3_query_prm__<$>(db)

State:
- State: Bad
- Exploitable: Yes


# Exploit description

1. Escape the apostrophe with '
2. No enclosure and special chars are allowed -> SQL injection
-->
<?php
# Init
$db = new SQLite3("/var/www/db/database.db");


# Sample
$tainted = $_REQUEST;
$tainted = $tainted["t"];
$sanitized = htmlspecialchars($tainted, ENT_COMPAT);
$dataflow = $sanitized;
$context = (("SELECT * FROM users WHERE password ='" . $dataflow) . "';");
$results = $db->query($context);
while(($row = $results->fetchArray()))
{
  echo(htmlentities(print_r($row, true)));
}

?>