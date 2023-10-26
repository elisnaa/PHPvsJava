<!--
# Sample information

Patterns:
- Source: _POST ==> Filters:[]
- Sanitization: strrpos_prm__<s>(needle) ==> Filters:[nums, letters, specials]
- Filters complete: Filters:[nums, letters, specials]
- Dataflow: assignment
- Context: xss_html_param_a
- Sink: trigger_error_prm__<c>(E_USER_ERROR)

State:
- State: Good
- Exploitable: Not found


# Exploit description

-->
<?php
# Init

# Sample
$tainted = $_POST;
$tainted = $tainted["t"];
$sanitized = strrpos($tainted, "needle");
$dataflow = $sanitized;
$context = (("<a href=\"" . $dataflow) . "\">link</a>");
trigger_error($context, E_USER_ERROR);

?>