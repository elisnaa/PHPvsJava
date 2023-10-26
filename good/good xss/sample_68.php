<!--
# Sample information

Patterns:
- Source: apache_request_headers ==> Filters:[]
- Sanitization: strpos_prm__<s>(needle) ==> Filters:[nums, letters, specials]
- Filters complete: Filters:[nums, letters, specials]
- Dataflow: assignment
- Context: xss_html_param
- Sink: printf_func_prm__<s>(Print this: %d)

State:
- State: Good
- Exploitable: Not found


# Exploit description

-->
<?php
# Init

# Sample
$tainted = apache_request_headers();
$tainted = $tainted["t"];
$sanitized = strpos($tainted, "needle");
$dataflow = $sanitized;
$context = (("<img src=\"" . $dataflow) . "\"/>");
printf("Print this: %d", $context);

?>