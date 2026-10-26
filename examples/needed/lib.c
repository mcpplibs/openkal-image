/* An image another image needs (`liboktwice.okso'), exporting one function. */
typedef long kal_intptr;
__attribute__((visibility("default"))) long twice(long v) { return 2 * v; }
static long counter = 40;
__attribute__((visibility("default"))) long next_value(void) { return ++counter; }
