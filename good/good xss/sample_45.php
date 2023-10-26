<!--
# Sample information

Patterns:
- Source: filter_input_prm__<c>(INPUT_GET)_<s>(t)_<c>(FILTER_SANITIZE_NUMBER_FLOAT) ==> Filters:[letters, specials]
- Sanitization: ctype_cntrl ==> Filters:[nums, letters, specials]
- Filters complete: Filters:[nums, letters, specials]
- Dataflow: assignment
- Context: xss_quotes
- Sink: printf_func_prm__<s>(Print this: %s)

State:
- State: Good
- Exploitable: Not found


# Exploit description

-->
<?php
# Init

# Sample
$tainted = filter_input(INPUT_GET, "t", FILTER_SANITIZE_NUMBER_FLOAT);
if(ctype_cntrl($tainted))
{
  $sanitized = $tainted;
  $dataflow = $sanitized;
  $context = (("Hello to \"" . $dataflow) . "\"");
  printf("Print this: %s", $context);
}

?>