/* expected: finding — direct getenv() to system() flow */
#include <stdlib.h>
int main(void) {
    system(getenv("CMD"));
    return 0;
}
