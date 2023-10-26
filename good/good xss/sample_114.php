<!--
# Sample information

Patterns:
- Source: filter_input_prm__<c>(INPUT_GET)_<s>(t)_<c>(FILTER_UNSAFE_RAW) ==> Filters:[]
- Sanitization: gettype_check_prm__<s>(boolean) ==> Filters:[nums, letters, specials]
- Filters complete: Filters:[nums, letters, specials]
- Dataflow: assignment
- Context: xss_apostrophe
- Sink: exit

State:
- State: Good
- Exploitable: Not found


# Exploit description

-->
<?php
# Init

# Sample
$tainted = filter_input(INPUT_GET, "t", FILTER_UNSAFE_RAW);
if(gettype($tainted) == "boolean")
{
  $sanitized = $tainted;
  $dataflow = $sanitized;
  $context = (("Hello to '" . $dataflow) . "'");
  exit($context);
}

?>