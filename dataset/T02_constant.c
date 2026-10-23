/* expected: clean — constant command */
#include <stdlib.h>
int main(void) {
    system("ls -l");
    return 0;
}
