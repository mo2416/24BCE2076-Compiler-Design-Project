/* expected: finding — taint through copies and cast */
#include <stdlib.h>
int main(void) {
    char *input = getenv("CMD");
    char *copy = input;
    const char *cmd = (const char *)copy;
    system(cmd);
    return 0;
}
