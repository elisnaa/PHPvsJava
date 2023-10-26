<!--
# Sample information

Patterns:
- Source: _POST ==> Filters:[]
- Sanitization: json_encode_prm__<c>(ENT_NOQUOTES) ==> Filters:[Filtered(&), Escape[\](", \)]
- Filters complete: Filters:[Filtered(&), Escape[\](", \)]
- Dataflow: assignment
- Context: xss_html_param
- Sink: print_func

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
$tainted = $_POST;
$sanitized = json_encode($tainted, ENT_NOQUOTES);
$dataflow = $sanitized;
$context = (("<img src=\"" . $dataflow) . "\"/>");
print($context);

?>