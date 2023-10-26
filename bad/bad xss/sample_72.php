<!--
# Sample information

Patterns:
- Source: filter_input_prm__<c>(INPUT_GET)_<s>(t)_<c>(FILTER_SANITIZE_SPECIAL_CHARS) ==> Filters:[Filtered(", &, ', <, >)]
- Sanitization: str_replace_prm__<s>(')_<s>('''') ==> Filters:[Escape[double](')]
- Filters complete: Filters:[Filtered(", &, ', <, >), Escape[double](')]
- Dataflow: assignment
- Context: xss_html_param_a
- Sink: printf_func_prm__<s>(Print this: %s)

State:
- State: Bad
- Exploitable: Yes


# Exploit description

1. It is possible to create a javascript context with: javascript:alert(1)
-->
<?php
# Init

# Sample
$tainted = filter_input(INPUT_GET, "t", FILTER_SANITIZE_SPECIAL_CHARS);
$sanitized = str_replace("'", "''", $tainted);
$dataflow = $sanitized;
$context = (("<a href=\"" . $dataflow) . "\">link</a>");
printf("Print this: %s", $context);

?>