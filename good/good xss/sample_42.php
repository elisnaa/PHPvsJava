<!--
# Sample information

Patterns:
- Source: getallheaders ==> Filters:[]
- Sanitization: settype_prm__<s>(float) ==> Filters:[letters, specials]
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
$tainted = getallheaders();
$tainted = $tainted["t"];
if(settype($tainted, "float"))
{
  $sanitized = $tainted;
  $dataflow = $sanitized;
  $context = (("Hello to '" . $dataflow) . "'");
  print($context);
}

?>