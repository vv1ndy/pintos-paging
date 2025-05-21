#include <stdio.h>
#include "tests/lib.h"
#include "tests/main.h"

void test_main(void) {
    msg("Running memory usage report...");
    syscall_memory_report();
    msg("Memory usage report completed.");
}