<!--
# Sample information

Patterns:
- Source: _GET ==> Filters:[]
- Sanitization: str_replace_prm__<s>(')_<s>('''') ==> Filters:[Escape[double](')]
- Filters complete: Filters:[Escape[double](')]
- Dataflow: assignment
- Context: xss_html_param_a
- Sink: exit

State:
- State: Bad
- Exploitable: Yes


# Exploit description

1. It is possible to create a javascript context with: javascript:alert(1)
-->
<?php
# Init

# Sample
$tainted = $_GET;
$tainted = $tainted["t"];
$sanitized = str_replace("'", "''", $tainted);
$dataflow = $sanitized;
$context = (("<a href=\"" . $dataflow) . "\">link</a>");
exit($context);

?>