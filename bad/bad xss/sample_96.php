<!--
# Sample information

Patterns:
- Source: filter_input_prm__<c>(INPUT_GET)_<s>(t)_<c>(FILTER_UNSAFE_RAW) ==> Filters:[]
- Sanitization: substr_replace_prm__<s>(bob)_<i>(50) ==> Filters:[]
- Filters complete: Filters:[]
- Dataflow: assignment
- Context: xss_html_param
- Sink: vprintf_prm__<s>(This%s)

State:
- State: Bad
- Exploitable: Yes


# Exploit description

1. Escape quotes with "
2. It is possible to create javascript parameters for: img attributes: onerror
-->
<?php
# Init

# Sample
$tainted = filter_input(INPUT_GET, "t", FILTER_UNSAFE_RAW);
$sanitized = substr_replace($tainted, "bob", 50);
$dataflow = $sanitized;
$context = (("<img src=\"" . $dataflow) . "\"/>");
vprintf("This%s", $context);

?>