<!--
# Sample information

Patterns:
- Source: _COOKIE ==> Filters:[]
- Sanitization: settype_prm__<s>(int) ==> Filters:[letters, specials]
- Filters complete: Filters:[letters, specials]
- Dataflow: assignment
- Context: xss_quotes
- Sink: user_error_prm_

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
if(settype($tainted, "int"))
{
  $sanitized = $tainted;
  $dataflow = $sanitized;
  $context = (("Hello to \"" . $dataflow) . "\"");
  user_error($context);
}

?>