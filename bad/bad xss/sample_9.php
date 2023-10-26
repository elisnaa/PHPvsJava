<!--
# Sample information

Patterns:
- Source: apache_request_headers ==> Filters:[]
- Sanitization: str_replace_prm__<s>(\w)_<s>() ==> Filters:[]
- Filters complete: Filters:[]
- Dataflow: assignment
- Context: xss_html_param_a
- Sink: user_error_prm_

State:
- State: Bad
- Exploitable: Yes


# Exploit description

1. It is possible to create a javascript context with: javascript:alert(1)
-->
<?php
# Init

# Sample
$tainted = apache_request_headers();
$tainted = $tainted["t"];
$sanitized = str_replace(" ", "", $tainted);
$dataflow = $sanitized;
$context = (("<a href=\"" . $dataflow) . "\">link</a>");
user_error($context);

?>