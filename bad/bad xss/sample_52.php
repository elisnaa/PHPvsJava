<!--
# Sample information

Patterns:
- Source: _COOKIE ==> Filters:[]
- Sanitization: json_encode_prm__<c>(ENT_COMPAT) ==> Filters:[Filtered(&), Escape[\](", \)]
- Filters complete: Filters:[Filtered(&), Escape[\](", \)]
- Dataflow: assignment
- Context: xss_html_param
- Sink: echo_func

State:
- State: Bad
- Exploitable: Yes


# Exploit description

1. Escape quotes with "
2. Escape quotes with "
3. It is possible to create javascript parameters for: img attributes: onerror
-->
<?php
# Init

# Sample
$tainted = $_COOKIE;
$sanitized = json_encode($tainted, ENT_COMPAT);
$dataflow = $sanitized;
$context = (("<img src=\"" . $dataflow) . "\"/>");
echo($context);

?>