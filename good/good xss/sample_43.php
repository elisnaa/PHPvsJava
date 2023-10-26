<!--
# Sample information

Patterns:
- Source: filter_input_array_prm__<c>(INPUT_GET)_<array>(<ae_k>(<s>(t),<c>(FILTER_SANITIZE_NUMBER_INT))) ==> Filters:[letters, specials]
- Sanitization: htmlentities_prm__<c>(ENT_COMPAT) ==> Filters:[Filtered(", &, <, >)]
- Filters complete: Filters:[letters, specials, Filtered(", &, <, >)]
- Dataflow: assignment
- Context: xss_quotes
- Sink: printf_func_prm__<s>(Print this: %s)

State:
- State: Good
- Exploitable: Not found


# Exploit description

-->
<?php
# Init

# Sample
$tainted = filter_input_array(INPUT_GET, ["t" => FILTER_SANITIZE_NUMBER_INT]);
$tainted = $tainted["t"];
$sanitized = htmlentities($tainted, ENT_COMPAT);
$dataflow = $sanitized;
$context = (("Hello to \"" . $dataflow) . "\"");
printf("Print this: %s", $context);

?>