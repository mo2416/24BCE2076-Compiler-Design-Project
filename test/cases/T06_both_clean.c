/* expect: clean */
#include <stdlib.h>
int main(int argc, char **argv) {
    char *cmd = getenv("CMD");
    if (argc > 1) {
        cmd = "ls";
    } else {
        cmd = "date";
    }
    system(cmd);
    return 0;
}
