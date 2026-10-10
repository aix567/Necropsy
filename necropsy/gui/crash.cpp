#include <cstdio>
int main() {
    volatile int* p = (int*)0x41414141;
    *p = 12345;
    return 0;
}
