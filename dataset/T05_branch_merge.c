/* expected: finding — tainted value reaches sink through a PHI merge */
#include <stdlib.h>
int main(int argc, char **argv) {
    char *cmd;
    if (argc > 1) {
        cmd = getenv("CMD");
    } else {
        cmd = "date";
    }
    system(cmd);
    return 0;
}
