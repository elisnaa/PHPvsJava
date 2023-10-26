<!--
# Sample information

Patterns:
- Source: filter_input_prm__<c>(INPUT_GET)_<s>(t)_<c>(FILTER_SANITIZE_ADD_SLASHES) ==> Filters:[Escape[\](", ', \)]
- Sanitization: html_entity_decode_prm_ ==> Filters:[]
- Filters complete: Filters:[Escape[\](", ', \)]
- Dataflow: assignment
- Context: xss_html_param
- Sink: echo_func

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
$tainted = filter_input(INPUT_GET, "t", FILTER_SANITIZE_ADD_SLASHES);
$sanitized = html_entity_decode($tainted);
$dataflow = $sanitized;
$context = (("<img src=\"" . $dataflow) . "\"/>");
echo($context);

?>