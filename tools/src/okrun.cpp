// okrun --- runs an ok image, or an okb (docs/okb.md): `okrun [options] image
// [arguments...]'. An okb runs this machine's architecture's entry.
//
//   --require-signature   refuse an image that is not signed
//   --trust <hex>         a public key (64 hexadecimal digits) whose images run;
//                         given at least once, an image signed by another is refused
//   --debugger            announce the image to gdb and lldb (GDB JIT interface)
//   --prof=<what>[:dir]   measure the image: calls, counters, perfmap (comma
//                         separated); the report goes to <dir>/okprof-<id>.json,
//                         which `okprof report' reads (OKRUN_PROF says the same)
//   --argv0=<name>        the name the image is told it was started as, its
//                         first argument, in place of the image's name (0.7.1)
//
// `okrun cache [list]' lists what the runner keeps for this machine (0.4: an
// image's data for this boot's base, snapshots, their markers); `okrun cache gc'
// removes what was prepared for another boot, and `--all' everything.
//
// The image is told its arguments are the image's (or the okb's) name, or the
// name `--argv0' gives, and what follows it. The images it needs are found
// beside it, in `lib/<arch>/' and `lib/' there, and in OKRUN_PATH.
//
// AN IMAGE THAT STARTS AN IMAGE FILE (0.7.1) starts it through this program,
// which the runner is told is its loader: the started image is entered by a
// runner as this one was, with this one's signature requirements, and observes
// the arguments its starter gave (openkal clause 7.6), the first by `--argv0'.
#include <okrun.h>

int main(int argc, char** argv) { return okrun_main(argc, argv); }
