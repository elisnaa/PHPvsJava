<!--
# Sample information

Patterns:
- Source: filter_input_array_prm__<c>(INPUT_GET)_<array>(<ae_k>(<s>(t),<c>(FILTER_SANITIZE_NUMBER_INT))) ==> Filters:[letters, specials]
- Sanitization: json_encode_prm__<c>(JSON_PRETTY_PRINT)_<i>(512) ==> Filters:[Filtered(&), Escape[\](\)]
- Filters complete: Filters:[letters, specials, Filtered(&), Escape[\](\)]
- Dataflow: assignment
- Context: xss_javascript
- Sink: exit

State:
- State: Good
- Exploitable: Not found


# Exploit description

-->
<?php
# Init

# Sample
$tainted = filter_input_array(INPUT_GET, ["t" => FILTER_SANITIZE_NUMBER_INT]);
$sanitized = json_encode($tainted, JSON_PRETTY_PRINT, 512);
$dataflow = $sanitized;
$pre = "<script>alert(\"Hello";
$post = "\");</script>";
$context = ($pre . ($dataflow . $post));
exit($context);

?>