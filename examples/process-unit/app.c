/* The actual OpenKal 0.24 declarations cross the image's calling convention.
 * The fifth retirement argument is intentional: Windows must present it in
 * the image ABI as well as the implementation's ABI. Full native lifecycle
 * controls live with the specification; this consumer verifies image binding. */
#include <openkal/process.h>
#include <openkal/stream.h>

int ok_main(void) {
    if (!(kal_process_props() & KAL_PROCESS_PROP_JOB_OBSERVE)) return 10;
    char reference[512];
    kal_uintptr used = 0;
    struct kal_job owned = {0}, observer = {0};
    kal_u32 state = KAL_JOB_UNKNOWN;
    if (kal_process_job_create(&owned, reference, sizeof reference, &used) != kal_ok) return 11;
    if (!used || used > sizeof reference) return 12;
    if (kal_process_job_open(reference, used, &observer) != kal_ok) return 13;
    if (kal_process_job_observe(observer, reference, used, &state) != kal_ok || state != KAL_JOB_OCCUPIED) return 14;
    kal_process_job_close(observer);
    /* An invalid continuation cannot establish retirement or authorize a move. */
    const struct kal_program_identity invalid = {0, 0};
    state = KAL_JOB_EMPTY;
    if (kal_process_job_retire(owned, reference, used, &invalid, &state) != kal_ok || state != KAL_JOB_UNKNOWN) return 15;
    if (kal_process_job_observe(owned, reference, used, &state) != kal_ok || state != KAL_JOB_OCCUPIED) return 16;
    kal_process_job_close(owned);
    const char message[] = "observable unit image: ok\n";
    return kal_stream_write(kal_stdout(), message, sizeof message - 1) == sizeof message - 1 ? 0 : 17;
}
