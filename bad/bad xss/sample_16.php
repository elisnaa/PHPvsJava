<!--
# Sample information

Patterns:
- Source: _REQUEST ==> Filters:[]
- Sanitization: str_replace_prm__<s>(')_<s>('''') ==> Filters:[Escape[double](')]
- Filters complete: Filters:[Escape[double](')]
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
$tainted = $_REQUEST;
$tainted = $tainted["t"];
$sanitized = str_replace("'", "''", $tainted);
$dataflow = $sanitized;
$context = (("<a href=\"" . $dataflow) . "\">link</a>");
user_error($context);

?>