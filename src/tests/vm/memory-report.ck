# -*- perl -*-
use strict;
use warnings;
use tests::tests;

check_expected (IGNORE_EXIT_CODES => 1, [<<'EOF']);
(memory-report) begin
(memory-report) Running memory usage report...
(memory-report) Memory usage report completed.
(memory-report) end
EOF

pass;
