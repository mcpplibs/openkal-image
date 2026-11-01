// okprof --- what an ok image did across openkal, measured by the runner that
// ran it (openkal-image 0.2).
//
//   okprof record [-o <dir>] [--what <list>] -- <program> [arguments...]
//       runs the program with OKRUN_PROF set, so that every image an okrun
//       beneath it runs (okrun itself, or a program that starts one, as an
//       editor starts its language server) writes <dir>/okprof-<id>.json when it
//       ends. <list> is any of calls, counters, perfmap (default calls,counters).
//   okprof report <report or directory>...
//       the calls each image made across openkal, by name and by interface,
//       with their counts and time; the counters and phases the program stated.
//       Several reports are summed.
//   okprof diff <before> <after>
//       the same names side by side, ordered by how much their time moved: the
//       input of a gate that compares two runs (an image and the same program
//       built for its system; two versions).
//
// A report is the runner's (run/src/prof.cpp); this program only reads and
// starts. It does not sample: a profiler of the system does, and on Linux the
// runner's `perfmap' names an image's addresses for it.
#include <okld.h>
#include <openkal.h>
import std;

namespace {

struct row { std::string name; std::uint64_t count = 0, ns = 0, value = 0; };
struct report {
    std::map<std::string, row> calls, counters, phases;
    std::uint64_t wall_ns = 0;
    int files = 0;
};

// --- reading a report ----------------------------------------------------------
// The runner writes one shape; this reads that shape: three arrays of flat
// objects whose values are strings and unsigned numbers.
struct reader {
    std::string_view s; std::size_t at = 0;
    void space() { while (at < s.size() && std::isspace(static_cast<unsigned char>(s[at]))) ++at; }
    bool eat(char c) { space(); if (at < s.size() && s[at] == c) { ++at; return true; } return false; }
    std::optional<std::string> text() {
        space();
        if (at >= s.size() || s[at] != '"') return std::nullopt;
        std::string out;
        for (++at; at < s.size() && s[at] != '"'; ++at) {
            if (s[at] == '\\' && at + 1 < s.size()) ++at;
            out += s[at];
        }
        if (at >= s.size()) return std::nullopt;
        ++at;
        return out;
    }
    std::optional<std::uint64_t> number() {
        space();
        std::uint64_t v = 0; bool any = false;
        while (at < s.size() && s[at] >= '0' && s[at] <= '9') { v = v * 10 + static_cast<std::uint64_t>(s[at++] - '0'); any = true; }
        return any ? std::optional<std::uint64_t>(v) : std::nullopt;
    }
    void skip_value() {
        space();
        if (at < s.size() && s[at] == '"') { text(); return; }
        if (at < s.size() && (s[at] == '[' || s[at] == '{')) {
            int depth = 0;
            for (; at < s.size(); ++at) {
                if (s[at] == '"') { text(); --at; continue; }
                if (s[at] == '[' || s[at] == '{') ++depth;
                if (s[at] == ']' || s[at] == '}') { if (--depth == 0) { ++at; return; } }
            }
            return;
        }
        while (at < s.size() && s[at] != ',' && s[at] != '}' && s[at] != ']') ++at;
    }
};

bool read_rows(reader& r, std::map<std::string, row>& into) {
    if (!r.eat('[')) return false;
    if (r.eat(']')) return true;
    do {
        if (!r.eat('{')) return false;
        row one;
        if (!r.eat('}')) {
            do {
                auto key = r.text();
                if (!key || !r.eat(':')) return false;
                if (*key == "name") { auto v = r.text(); if (!v) return false; one.name = *v; }
                else if (*key == "count") { auto v = r.number(); if (!v) return false; one.count = *v; }
                else if (*key == "ns") { auto v = r.number(); if (!v) return false; one.ns = *v; }
                else if (*key == "value") { auto v = r.number(); if (!v) return false; one.value = *v; }
                else r.skip_value();
            } while (r.eat(','));
            if (!r.eat('}')) return false;
        }
        auto& have = into[one.name];
        have.name = one.name;
        have.count += one.count;
        have.ns += one.ns;
        have.value += one.value;
    } while (r.eat(','));
    return r.eat(']');
}

bool read_report(const std::filesystem::path& file, report& into) {
    std::ifstream in(file, std::ios::binary);
    if (!in) return false;
    const std::string text((std::istreambuf_iterator<char>(in)), {});
    reader r{ text };
    if (!r.eat('{')) return false;
    do {
        auto key = r.text();
        if (!key || !r.eat(':')) return false;
        if (*key == "calls") { if (!read_rows(r, into.calls)) return false; }
        else if (*key == "counters") { if (!read_rows(r, into.counters)) return false; }
        else if (*key == "phases") { if (!read_rows(r, into.phases)) return false; }
        else if (*key == "wall_ns") { auto v = r.number(); if (v) into.wall_ns += *v; }
        else r.skip_value();
    } while (r.eat(','));
    ++into.files;
    return true;
}

bool read_reports(const std::vector<std::string>& args, report& into) {
    for (auto const& a : args) {
        std::error_code ec;
        if (std::filesystem::is_directory(a, ec)) {
            for (auto const& e : std::filesystem::directory_iterator(a, ec)) {
                const auto name = e.path().filename().string();
                if (name.starts_with("okprof-") && name.ends_with(".json") && !read_report(e.path(), into)) {
                    std::println(std::cerr, "okprof: {} is not a report", e.path().string());
                    return false;
                }
            }
        } else if (!read_report(a, into)) {
            std::println(std::cerr, "okprof: {} is not a report", a);
            return false;
        }
    }
    if (into.files == 0) { std::println(std::cerr, "okprof: no report was found"); return false; }
    return true;
}

// The interface a name belongs to, as libokld reads it (`kal_alloc' is
// openkal.memory, `kal_stdout' openkal.stream).
std::string interface_of(const std::string& name) {
    static const char* const names[] = {
        "abort", "stream", "memory", "env", "time", "random", "fs", "process", "task", "exec",
        "terminal", "net", "datagram", "space", "timeout", "map", "region", "prof", "debug" };
    const okld_u64 bits = okld_interface_of(name.c_str());
    for (unsigned i = 0; i < sizeof names / sizeof names[0]; ++i)
        if (bits & (okld_u64{1} << i)) return std::string("openkal.") + names[i];
    if (name == "kal_version" || name == "kal_interfaces") return "openkal.version";
    return "?";
}

std::string ms(std::uint64_t ns) { return std::format("{:.3f} ms", static_cast<double>(ns) / 1e6); }

int report_cmd(const std::vector<std::string>& args) {
    report r;
    if (!read_reports(args, r)) return 2;
    std::println("{} report{}; the images ran {} in all", r.files, r.files == 1 ? "" : "s", ms(r.wall_ns));
    std::vector<row> calls;
    for (auto const& [k, v] : r.calls) calls.push_back(v);
    std::ranges::sort(calls, [](const row& a, const row& b) { return a.ns > b.ns; });
    std::map<std::string, row> byInterface;
    std::uint64_t total = 0;
    for (auto const& c : calls) {
        auto& i = byInterface[interface_of(c.name)];
        i.name = interface_of(c.name);
        i.count += c.count;
        i.ns += c.ns;
        total += c.ns;
    }
    std::println("\ncalls across openkal, by interface ({} in all)", ms(total));
    std::vector<row> ifaces;
    for (auto const& [k, v] : byInterface) ifaces.push_back(v);
    std::ranges::sort(ifaces, [](const row& a, const row& b) { return a.ns > b.ns; });
    for (auto const& i : ifaces)
        std::println("  {:<20} {:>12} calls  {:>14}", i.name, i.count, ms(i.ns));
    std::println("\ncalls across openkal, by name");
    for (auto const& c : calls)
        std::println("  {:<32} {:>12} calls  {:>14}  {:>9} ns each", c.name, c.count, ms(c.ns),
                     c.count ? c.ns / c.count : 0);
    if (!r.counters.empty()) {
        std::println("\ncounters the program stated");
        for (auto const& [k, v] : r.counters) std::println("  {:<40} {:>16}", k, v.value);
    }
    if (!r.phases.empty()) {
        std::println("\nphases the program stated");
        for (auto const& [k, v] : r.phases) std::println("  {:<40} {:>8} times  {:>14}", k, v.count, ms(v.ns));
    }
    return 0;
}

int diff_cmd(const std::vector<std::string>& args) {
    if (args.size() != 2) { std::println(std::cerr, "okprof diff <before> <after>"); return 2; }
    report a, b;
    if (!read_reports({args[0]}, a) || !read_reports({args[1]}, b)) return 2;
    std::set<std::string> names;
    for (auto const& [k, v] : a.calls) names.insert(k);
    for (auto const& [k, v] : b.calls) names.insert(k);
    struct moved { std::string name; std::int64_t delta; row before, after; };
    std::vector<moved> rows;
    for (auto const& n : names) {
        const row before = a.calls.contains(n) ? a.calls.at(n) : row{n};
        const row after = b.calls.contains(n) ? b.calls.at(n) : row{n};
        rows.push_back({n, static_cast<std::int64_t>(after.ns) - static_cast<std::int64_t>(before.ns), before, after});
    }
    std::ranges::sort(rows, [](const moved& x, const moved& y) { return std::llabs(x.delta) > std::llabs(y.delta); });
    std::println("{:<32} {:>12} {:>12}  {:>14} {:>14}  {:>9}", "name", "calls before", "calls after",
                 "time before", "time after", "ratio");
    for (auto const& m : rows)
        std::println("{:<32} {:>12} {:>12}  {:>14} {:>14}  {:>9}", m.name, m.before.count, m.after.count,
                     ms(m.before.ns), ms(m.after.ns),
                     m.before.ns ? std::format("{:.2f}", static_cast<double>(m.after.ns) / static_cast<double>(m.before.ns))
                                 : std::string("new"));
    std::println("\nwall time {} -> {}", ms(a.wall_ns), ms(b.wall_ns));
    return 0;
}

// --- starting the program ---------------------------------------------------------
// A name as openkal names things: the supplied directory that is the longest
// prefix of it, and the rest. A name without a separator is looked for on PATH.
bool locate(const std::string& path, kal_dir& dir, std::string& rest) {
    auto separator = [](char c) { return c == '/' || c == '\\'; };
    const bool absolute = !path.empty() && (separator(path[0]) || (path.size() > 1 && path[1] == ':'));
    if (!absolute) {
        char name[8]; kal_uintptr len = 0;
        if (kal_fs_preopen(0, &dir, name, sizeof name, &len) != kal_ok) return false;
        rest = path;
        return true;
    }
    std::size_t best = 0; bool found = false;
    for (kal_uintptr i = 0; i < kal_fs_preopen_count(); ++i) {
        kal_dir d{}; char name[1024]; kal_uintptr len = 0;
        if (kal_fs_preopen(i, &d, name, sizeof name, &len) != kal_ok || len == 0 || len >= sizeof name) continue;
        const std::string_view n(name, len);
        if (!path.starts_with(n)) continue;
        if (!separator(n.back()) && path.size() > len && !separator(path[len])) continue;
        if (found && len <= best) continue;
        best = len; found = true; dir = d;
    }
    if (!found) return false;
    rest = path.substr(best);
    while (!rest.empty() && separator(rest.front())) rest.erase(0, 1);
    return true;
}

std::optional<std::string> on_path(const std::string& name) {
    if (name.find('/') != std::string::npos || name.find('\\') != std::string::npos) return name;
    char list[8192];
    const kal_intptr n = kal_env_var("PATH", 4, list, sizeof list - 1);
    if (n <= 0 || n >= static_cast<kal_intptr>(sizeof list)) return std::nullopt;
    char system[16];
    const kal_intptr sn = kal_env_system(system, sizeof system);
    const bool windows = sn == 7 && std::string_view(system, 7) == "windows";
    const char sep = windows ? ';' : ':';
    for (auto part : std::views::split(std::string_view(list, static_cast<std::size_t>(n)), sep)) {
        std::string dirName(part.begin(), part.end());
        if (dirName.empty()) continue;
        for (const char* ext : {"", ".exe"}) {
            if (!windows && *ext) continue;
            const std::string candidate = dirName + "/" + name + ext;
            kal_dir d{}; std::string rest;
            if (!locate(candidate, d, rest)) continue;
            kal_node_info info{};
            info.self_size = sizeof info;
            if (kal_fs_info(d, rest.c_str(), rest.size(), 0, KAL_INFO_KIND, &info) == kal_ok && info.kind == kal_node_file)
                return candidate;
        }
    }
    return std::nullopt;
}

int record_cmd(std::vector<std::string> args) {
    std::string dir = ".", what = "calls,counters";
    while (!args.empty() && args.front() != "--") {
        if (args.front() == "-o" && args.size() > 1) { dir = args[1]; args.erase(args.begin(), args.begin() + 2); continue; }
        if (args.front() == "--what" && args.size() > 1) { what = args[1]; args.erase(args.begin(), args.begin() + 2); continue; }
        std::println(std::cerr, "okprof record: unknown option {}", args.front());
        return 2;
    }
    if (args.empty() || args.size() < 2) { std::println(std::cerr, "okprof record [-o <dir>] [--what <list>] -- <program> [arguments...]"); return 2; }
    args.erase(args.begin());   // "--"
    std::error_code ec;
    std::filesystem::create_directories(dir, ec);
    const auto program = on_path(args.front());
    if (!program) { std::println(std::cerr, "okprof: {} is not found", args.front()); return 2; }
    kal_dir base{}; std::string rest;
    if (!locate(*program, base, rest)) { std::println(std::cerr, "okprof: {} is beneath no directory this program was given", *program); return 2; }

    // The environment, with OKRUN_PROF stated (replacing any it had).
    const std::string spec = std::format("OKRUN_PROF={}:{}", what, std::filesystem::absolute(dir, ec).generic_string());
    std::vector<std::string> env;
    for (kal_uintptr i = 0; i < kal_env_var_count(); ++i) {
        char entry[16384];
        const kal_intptr n = kal_env_var_at(i, entry, sizeof entry);
        if (n <= 0 || n >= static_cast<kal_intptr>(sizeof entry)) continue;
        std::string e(entry, static_cast<std::size_t>(n));
        if (e.starts_with("OKRUN_PROF=")) continue;
        env.push_back(std::move(e));
    }
    env.push_back(spec);
    std::vector<const char*> argv, envp;
    std::vector<kal_uintptr> argl, envl;
    for (auto const& a : args) { argv.push_back(a.c_str()); argl.push_back(a.size()); }
    for (auto const& e : env) { envp.push_back(e.c_str()); envl.push_back(e.size()); }
    kal_dir work{};
    {
        char name[8]; kal_uintptr len = 0;
        kal_fs_preopen(0, &work, name, sizeof name, &len);
    }
    const kal_spawn how{ base, work, nullptr, nullptr, 0, 0 };
    const kal_spawn_streams streams{ 0, 0, 0 };
    kal_process child{};
    const int e = kal_process_spawn(&how, rest.c_str(), rest.size(), argv.data(), argl.data(), argv.size(),
                                    envp.data(), envl.data(), envp.size(), &streams, &child);
    if (e != kal_ok) { std::println(std::cerr, "okprof: {} could not be started ({})", *program, e); return 2; }
    int status = 0, terminated = 0;
    kal_process_wait(child, &status, &terminated);
    kal_process_close(child);
    std::println(std::cerr, "okprof: the reports are in {}; `okprof report {}' reads them", dir, dir);
    return terminated ? 128 + status : status;
}

}  // namespace

int main(int argc, char** argv) {
    std::vector<std::string> args(argv + 1, argv + argc);
    if (args.empty()) {
        std::println(std::cerr, "okprof record|report|diff ...  (see the head of tools/src/okprof.cpp)");
        return 2;
    }
    const std::string command = args.front();
    args.erase(args.begin());
    if (command == "record") return record_cmd(std::move(args));
    if (command == "report") return report_cmd(args);
    if (command == "diff") return diff_cmd(args);
    std::println(std::cerr, "okprof: unknown command {}", command);
    return 2;
}
