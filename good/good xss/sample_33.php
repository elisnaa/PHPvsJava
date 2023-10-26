<!--
# Sample information

Patterns:
- Source: _GET ==> Filters:[]
- Sanitization: substr_count_prm__<s>(needle) ==> Filters:[nums, letters, specials]
- Filters complete: Filters:[nums, letters, specials]
- Dataflow: assignment
- Context: xss_apostrophe
- Sink: echo_func

State:
- State: Good
- Exploitable: Not found


# Exploit description

-->
<?php
# Init

# Sample
$tainted = $_GET;
$tainted = $tainted["t"];
$sanitized = substr_count($tainted, "needle");
$dataflow = $sanitized;
$context = (("Hello to '" . $dataflow) . "'");
echo($context);

?>