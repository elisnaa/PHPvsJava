<!--
# Sample information

Patterns:
- Source: getallheaders ==> Filters:[]
- Sanitization: is_string ==> Filters:[]
- Filters complete: Filters:[]
- Dataflow: assignment
- Context: xss_plain
- Sink: user_error_prm_

State:
- State: Bad
- Exploitable: Yes


# Exploit description

1. Create script tag with <script>
-->
<?php
# Init

# Sample
$tainted = getallheaders();
$tainted = $tainted["t"];
if(is_string($tainted))
{
  $sanitized = $tainted;
  $dataflow = $sanitized;
  $context = ("Hello" . $dataflow);
  user_error($context);
}

?>