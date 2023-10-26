<!--
# Sample information

Patterns:
- Source: filter_input_prm__<c>(INPUT_GET)_<s>(t)_<c>(FILTER_SANITIZE_NUMBER_FLOAT) ==> Filters:[letters, specials]
- Sanitization: cast_int ==> Filters:[letters, specials]
- Filters complete: Filters:[letters, specials]
- Dataflow: assignment
- Context: xss_apostrophe
- Sink: print_func

State:
- State: Good
- Exploitable: Not found


# Exploit description

-->
<?php
# Init

# Sample
$tainted = filter_input(INPUT_GET, "t", FILTER_SANITIZE_NUMBER_FLOAT);
$sanitized = (int)($tainted);
$dataflow = $sanitized;
$context = (("Hello to '" . $dataflow) . "'");
print($context);

?>