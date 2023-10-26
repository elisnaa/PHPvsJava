<!--
# Sample information

Patterns:
- Source: _POST ==> Filters:[]
- Sanitization: json_encode_prm__<c>(JSON_PRETTY_PRINT)_<i>(512) ==> Filters:[Filtered(&), Escape[\](\)]
- Filters complete: Filters:[Filtered(&), Escape[\](\)]
- Dataflow: assignment
- Context: xss_quotes
- Sink: printf_func_prm__<s>(Print this: %s)

State:
- State: Bad
- Exploitable: Yes


# Exploit description

1. Escape quotes with "
2. Create script tag with <script>
3. Quotes are useless inside plain html context for XSS
-->
<?php
# Init

# Sample
$tainted = $_POST;
$sanitized = json_encode($tainted, JSON_PRETTY_PRINT, 512);
$dataflow = $sanitized;
$context = (("Hello to \"" . $dataflow) . "\"");
printf("Print this: %s", $context);

?>