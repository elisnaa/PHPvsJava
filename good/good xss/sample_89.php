<!--
# Sample information

Patterns:
- Source: _REQUEST ==> Filters:[]
- Sanitization: preg_match_all_prm__<s>(_^[A-Za-z0-9]*$_) ==> Filters:[specials]
- Filters complete: Filters:[specials]
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
$tainted = $_REQUEST;
$tainted = $tainted["t"];
if(preg_match_all("/^[A-Za-z0-9]*$/", $tainted))
{
  $sanitized = $tainted;
  $dataflow = $sanitized;
  $context = ("Hello" . $dataflow);
  user_error($context);
}

?>