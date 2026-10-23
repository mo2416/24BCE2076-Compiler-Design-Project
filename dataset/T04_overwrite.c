/* expected: clean — tainted local overwritten */
#include <stdlib.h>
int main(void) {
    char *cmd = getenv("CMD");
    cmd = "date";
    system(cmd);
    return 0;
}
