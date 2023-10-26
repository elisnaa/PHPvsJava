<!--
# Sample information

Patterns:
- Source: _COOKIE ==> Filters:[]
- Sanitization: filter_var_prm__<c>(FILTER_SANITIZE_SPECIAL_CHARS) ==> Filters:[Filtered(", &, ', <, >)]
- Filters complete: Filters:[Filtered(", &, ', <, >)]
- Dataflow: assignment
- Context: xss_plain
- Sink: printf_func_prm__<s>(Print this: %s)

State:
- State: Good
- Exploitable: Not found


# Exploit description

-->
<?php
# Init

# Sample
$tainted = $_COOKIE;
$tainted = $tainted["t"];
$sanitized = filter_var($tainted, FILTER_SANITIZE_SPECIAL_CHARS);
$dataflow = $sanitized;
$context = ("Hello" . $dataflow);
printf("Print this: %s", $context);

?>