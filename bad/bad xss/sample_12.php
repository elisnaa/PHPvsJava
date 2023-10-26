<!--
# Sample information

Patterns:
- Source: getallheaders ==> Filters:[]
- Sanitization: filter_var_prm__<c>(FILTER_SANITIZE_ADD_SLASHES) ==> Filters:[Escape[\](", ', \)]
- Filters complete: Filters:[Escape[\](", ', \)]
- Dataflow: assignment
- Context: xss_apostrophe
- Sink: print_func

State:
- State: Bad
- Exploitable: Yes


# Exploit description

1. Create script tag with <script>
2. Apostrophe are useless inside plain html context for XSS
-->
<?php
# Init

# Sample
$tainted = getallheaders();
$tainted = $tainted["t"];
$sanitized = filter_var($tainted, FILTER_SANITIZE_ADD_SLASHES);
$dataflow = $sanitized;
$context = (("Hello to '" . $dataflow) . "'");
print($context);

?>