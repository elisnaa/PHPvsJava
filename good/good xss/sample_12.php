<!--
# Sample information

Patterns:
- Source: _REQUEST ==> Filters:[]
- Sanitization: is_int ==> Filters:[letters, specials]
- Filters complete: Filters:[letters, specials]
- Dataflow: assignment
- Context: xss_apostrophe
- Sink: printf_func_prm__<s>(Print this: %s)

State:
- State: Good
- Exploitable: Not found


# Exploit description

-->
<?php
# Init

# Sample
$tainted = $_REQUEST;
$tainted = $tainted["t"];
if(is_int($tainted))
{
  $sanitized = $tainted;
  $dataflow = $sanitized;
  $context = (("Hello to '" . $dataflow) . "'");
  printf("Print this: %s", $context);
}

?>