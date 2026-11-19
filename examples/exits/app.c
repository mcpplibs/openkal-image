/* An image that ends the program itself (0.7.1): its main calls kal_exit,
 * which passes through the runner (`own_kal_exit'), rather than returning to
 * it. The runner's task that waits for the requests to end returns before the
 * program ends, as where an image's main returns (tools/tests/debugger_end.py).
 */
void kal_exit(int status);

__attribute__((visibility("default"))) int ok_main(void) {
    kal_exit(0);
    return 1;
}
