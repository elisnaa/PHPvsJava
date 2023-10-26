<!--
# Sample information

Patterns:
- Source: _COOKIE ==> Filters:[]
- Sanitization: zlib_encode_prm__<c>(ZLIB_ENCODING_DEFLATE) ==> Filters:[nums, letters, specials]
- Filters complete: Filters:[nums, letters, specials]
- Dataflow: assignment
- Context: xss_html_param
- Sink: printf_func_prm__<s>(Print this: %d)

State:
- State: Good
- Exploitable: Not found


# Exploit description

-->
<?php
# Init

# Sample
$tainted = $_COOKIE;
$tainted = $tainted["t"];
$sanitized = zlib_encode($tainted, ZLIB_ENCODING_DEFLATE);
$dataflow = $sanitized;
$context = (("<img src=\"" . $dataflow) . "\"/>");
printf("Print this: %d", $context);

?>