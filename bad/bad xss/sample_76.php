<!--
# Sample information

Patterns:
- Source: _POST ==> Filters:[]
- Sanitization: settype_prm__<s>(string) ==> Filters:[]
- Filters complete: Filters:[]
- Dataflow: assignment
- Context: xss_javascript
- Sink: vprintf_prm__<s>(This%s)

State:
- State: Bad
- Exploitable: Yes


# Exploit description

1. Escape quotes with "
2. The ; can be used to chain commands
-->
<?php
# Init

# Sample
$tainted = $_POST;
$tainted = $tainted["t"];
if(settype($tainted, "string"))
{
  $sanitized = $tainted;
  $dataflow = $sanitized;
  $pre = "<script>alert(\"Hello";
  $post = "\");</script>";
  $context = ($pre . ($dataflow . $post));
  vprintf("This%s", $context);
}

?>