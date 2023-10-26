<!--
# Sample information

Patterns:
- Source: filter_input_prm__<c>(INPUT_GET)_<s>(t)_<c>(FILTER_UNSAFE_RAW) ==> Filters:[]
- Sanitization: password_hash_prm__<c>(PASSWORD_DEFAULT) ==> Filters:[nums, letters, specials]
- Filters complete: Filters:[nums, letters, specials]
- Dataflow: assignment
- Context: xss_quotes
- Sink: vprintf_prm__<s>(This%s)

State:
- State: Good
- Exploitable: Not found


# Exploit description

-->
<?php
# Init

# Sample
$tainted = filter_input(INPUT_GET, "t", FILTER_UNSAFE_RAW);
$sanitized = password_hash($tainted, PASSWORD_DEFAULT);
$dataflow = $sanitized;
$context = (("Hello to \"" . $dataflow) . "\"");
vprintf("This%s", $context);

?>