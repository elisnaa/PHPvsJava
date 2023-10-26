<!--
# Sample information

Patterns:
- Source: getallheaders ==> Filters:[]
- Sanitization: crc32 ==> Filters:[letters, specials]
- Filters complete: Filters:[letters, specials]
- Dataflow: assignment
- Context: sql_quotes
- Sink: sqlite3_query_prm__<$>(db)

State:
- State: Good
- Exploitable: Not found


# Exploit description

-->
<?php
# Init
$db = new SQLite3("/var/www/db/database.db");


# Sample
$tainted = getallheaders();
$tainted = $tainted["t"];
$sanitized = crc32($tainted);
$dataflow = $sanitized;
$context = (("SELECT * FROM users WHERE password =\"" . $dataflow) . "\";");
$results = $db->query($context);
while(($row = $results->fetchArray()))
{
  echo(htmlentities(print_r($row, true)));
}

?>