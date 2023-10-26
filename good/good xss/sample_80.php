<!--
# Sample information

Patterns:
- Source: filter_input_prm__<c>(INPUT_GET)_<s>(t)_<c>(FILTER_UNSAFE_RAW) ==> Filters:[]
- Sanitization: strip_tags_1 ==> Filters:[Filtered(<, >)]
- Filters complete: Filters:[Filtered(<, >)]
- Dataflow: assignment
- Context: xss_plain
- Sink: user_error_prm_

State:
- State: Good
- Exploitable: Not found


# Exploit description

-->
<?php
# Init

# Sample
$tainted = filter_input(INPUT_GET, "t", FILTER_UNSAFE_RAW);
$sanitized = strip_tags($tainted);
$dataflow = $sanitized;
$context = ("Hello" . $dataflow);
user_error($context);

?>