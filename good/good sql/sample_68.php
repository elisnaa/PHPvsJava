<!--
# Sample information

Patterns:
- Source: filter_input_array_prm__<c>(INPUT_GET)_<array>(<ae_k>(<s>(t),<c>(FILTER_SANITIZE_NUMBER_FLOAT))) ==> Filters:[letters, specials]
- Sanitization: htmlspecialchars_1 ==> Filters:[Filtered(", &, <, >)]
- Filters complete: Filters:[letters, specials, Filtered(", &, <, >)]
- Dataflow: assignment
- Context: sql_plain
- Sink: pg_query_prm__<$>(db)

State:
- State: Good
- Exploitable: Not found


# Exploit description

-->
<?php
# Init
$db = pg_pconnect("host=postgres-server port=5432 user=postgres password=postgres123 dbname=myDB");


# Sample
$tainted = filter_input_array(INPUT_GET, ["t" => FILTER_SANITIZE_NUMBER_FLOAT]);
$tainted = $tainted["t"];
$sanitized = htmlspecialchars($tainted);
$dataflow = $sanitized;
$context = (("SELECT * FROM users WHERE pin =" . $dataflow) . ";");
$result = pg_query($db, $context);
while(($row = pg_fetch_row($result)))
{
  echo(htmlentities(print_r($row, true)));
}

?>