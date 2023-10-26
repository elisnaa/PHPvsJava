<!--
# Sample information

Patterns:
- Source: apache_request_headers ==> Filters:[]
- Sanitization: settype_prm__<s>(int) ==> Filters:[letters, specials]
- Filters complete: Filters:[letters, specials]
- Dataflow: assignment
- Context: xss_javascript
- Sink: vprintf_prm__<s>(This%d)

State:
- State: Good
- Exploitable: Not found


# Exploit description

-->
<?php
# Init

# Sample
$tainted = apache_request_headers();
$tainted = $tainted["t"];
if(settype($tainted, "int"))
{
  $sanitized = $tainted;
  $dataflow = $sanitized;
  $pre = "<script>alert(\"Hello";
  $post = "\");</script>";
  $context = ($pre . ($dataflow . $post));
  vprintf("This%d", $context);
}

?>