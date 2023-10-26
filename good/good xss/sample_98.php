<!--
# Sample information

Patterns:
- Source: filter_input_array_prm__<c>(INPUT_GET)_<array>(<ae_k>(<s>(t),<c>(FILTER_SANITIZE_NUMBER_INT))) ==> Filters:[letters, specials]
- Sanitization: ctype_alpha ==> Filters:[nums, specials]
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
$tainted = filter_input_array(INPUT_GET, ["t" => FILTER_SANITIZE_NUMBER_INT]);
$tainted = $tainted["t"];
if(ctype_alpha($tainted))
{
  $sanitized = $tainted;
  $dataflow = $sanitized;
  $context = (("Hello to '" . $dataflow) . "'");
  exit($context);
}

?>