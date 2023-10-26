<!--
# Sample information

Patterns:
- Source: _GET ==> Filters:[]
- Sanitization: ternerary_white_listing ==> Filters:[nums, letters, specials]
- Filters complete: Filters:[nums, letters, specials]
- Dataflow: assignment
- Context: xss_quotes
- Sink: printf_func_prm__<s>(Print this: %d)

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
$sanitized = (($tainted == "DESC") ? "DESC" : "ASC");
$dataflow = $sanitized;
$context = (("Hello to \"" . $dataflow) . "\"");
printf("Print this: %d", $context);

?>