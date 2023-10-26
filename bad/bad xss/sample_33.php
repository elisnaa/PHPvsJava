<!--
# Sample information

Patterns:
- Source: _POST ==> Filters:[]
- Sanitization: str_replace_prm__<s>(')_<s>('''') ==> Filters:[Escape[double](')]
- Filters complete: Filters:[Escape[double](')]
- Dataflow: assignment
- Context: xss_quotes
- Sink: user_error_prm_

State:
- State: Bad
- Exploitable: Yes


# Exploit description

1. Create script tag with <script>
2. Quotes are useless inside plain html context for XSS
-->
<?php
# Init

# Sample
$tainted = $_POST;
$tainted = $tainted["t"];
$sanitized = str_replace("'", "''", $tainted);
$dataflow = $sanitized;
$context = (("Hello to \"" . $dataflow) . "\"");
user_error($context);

?>