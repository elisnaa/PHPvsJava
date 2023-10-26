<!--
# Sample information

Patterns:
- Source: filter_input_prm__<c>(INPUT_GET)_<s>(t)_<c>(FILTER_UNSAFE_RAW) ==> Filters:[]
- Sanitization: nosanitization ==> Filters:[]
- Filters complete: Filters:[]
- Dataflow: assignment
- Context: xss_html_param_a
- Sink: exit

State:
- State: Bad
- Exploitable: Yes


# Exploit description

1. It is possible to create a javascript context with: javascript:alert(1)
-->
<?php
# Init

# Sample
$tainted = filter_input(INPUT_GET, "t", FILTER_UNSAFE_RAW);
$sanitized = $tainted;
$dataflow = $sanitized;
$context = (("<a href=\"" . $dataflow) . "\">link</a>");
exit($context);

?>