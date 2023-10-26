<!--
# Sample information

Patterns:
- Source: filter_input_array_prm__<c>(INPUT_GET)_<array>(<ae_k>(<s>(t),<c>(FILTER_SANITIZE_ADD_SLASHES))) ==> Filters:[Escape[\](", ', \)]
- Sanitization: html_entity_decode_prm_ ==> Filters:[]
- Filters complete: Filters:[Escape[\](", ', \)]
- Dataflow: assignment
- Context: xss_quotes
- Sink: vprintf_prm__<s>(This%s)

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
$tainted = filter_input_array(INPUT_GET, ["t" => FILTER_SANITIZE_ADD_SLASHES]);
$tainted = $tainted["t"];
$sanitized = html_entity_decode($tainted);
$dataflow = $sanitized;
$context = (("Hello to \"" . $dataflow) . "\"");
vprintf("This%s", $context);

?>