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
//   okprof report --flame <report or directory>...
//       the stacks sampled (`samples'), folded --- the outermost frame first,
//       `;' between, then the count --- which a flame graph is drawn from.
//   okprof report --format=trace <report or directory>...
//       a timeline for Perfetto or chrome://tracing: a row for each program,
//       its start's moments (`phases') and each sample on one time axis.
//   okprof report --order <image> <report or directory>...
//       the image's functions in the order its start first executed their pages
//       (`touch'): a symbol ordering file, which a link lays the code out by.
//   okprof report --names <directory>
//       the names a program reached through its directories (`record --what
//       names'), by directory: how many it asked for and found absent.
//   okprof diff <before> <after>
//       the same names side by side, ordered by how much their time moved: the
//       input of a gate that compares two runs (an image and the same program
//       built for its system; two versions).
//
// A report is the runner's (run/src/prof.cpp); this program only reads and
// starts. Samples and touches are taken by the implementation (openkal 0.23)
// and named by the runner; on Linux the runner's `perfmap' also names an
// image's addresses for the system's profiler.
#include <okld.h>
#include <openkal.h>
import std;

namespace {

struct row { std::string name; std::uint64_t count = 0, ns = 0, value = 0; };
struct moment { std::string name; std::uint64_t ns = 0, faults = 0; };
struct sample_at { std::uint64_t ns = 0, stack = 0, context = 0; };
// One program's report, for what is not summed: a timeline, an order.
struct program {
    std::uint64_t id = 0, started_ns = 0;
    std::string image;
    std::vector<moment> moments;
    std::vector<std::string> stacks;
    std::vector<sample_at> timeline;
    std::vector<std::pair<std::string, std::uint64_t>> touches;   // image, file offset
    std::uint64_t page = 4096;
};
struct report {
    std::map<std::string, row> calls, counters, phases;
    std::map<std::string, std::uint64_t> folded;   // a stack, and how often it was sampled
    std::vector<program> programs;
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

// An array of flat objects, each given to `each' as its keys' strings and numbers.
template <class Each>
bool read_objects(reader& r, Each each) {
    if (!r.eat('[')) return false;
    if (r.eat(']')) return true;
    do {
        if (!r.eat('{')) return false;
        std::map<std::string, std::string> text;
        std::map<std::string, std::uint64_t> number;
        if (!r.eat('}')) {
            do {
                auto key = r.text();
                if (!key || !r.eat(':')) return false;
                r.space();
                if (r.at < r.s.size() && r.s[r.at] == '"') { auto v = r.text(); if (!v) return false; text[*key] = *v; }
                else if (auto v = r.number()) number[*key] = *v;
                else r.skip_value();
            } while (r.eat(','));
            if (!r.eat('}')) return false;
        }
        each(text, number);
    } while (r.eat(','));
    return r.eat(']');
}

bool read_report(const std::filesystem::path& file, report& into) {
    std::ifstream in(file, std::ios::binary);
    if (!in) return false;
    const std::string text((std::istreambuf_iterator<char>(in)), {});
    reader r{ text };
    if (!r.eat('{')) return false;
    program one;
    do {
        auto key = r.text();
        if (!key || !r.eat(':')) return false;
        if (*key == "calls") { if (!read_rows(r, into.calls)) return false; }
        else if (*key == "counters") { if (!read_rows(r, into.counters)) return false; }
        else if (*key == "phases") { if (!read_rows(r, into.phases)) return false; }
        else if (*key == "wall_ns") { auto v = r.number(); if (v) into.wall_ns += *v; }
        else if (*key == "id") { auto v = r.number(); if (v) one.id = *v; }
        else if (*key == "started_ns") { auto v = r.number(); if (v) one.started_ns = *v; }
        else if (*key == "image") { auto v = r.text(); if (v) one.image = *v; }
        else if (*key == "page") { auto v = r.number(); if (v) one.page = *v; }
        else if (*key == "moments") {
            if (!read_objects(r, [&](auto& t, auto& n) { one.moments.push_back({ t["name"], n["ns"], n["faults"] }); })) return false;
        } else if (*key == "stacks") {
            if (!read_objects(r, [&](auto& t, auto& n) {
                    one.stacks.push_back(t["stack"]);
                    into.folded[t["stack"]] += n["count"];
                })) return false;
        } else if (*key == "touches") {
            if (!read_objects(r, [&](auto& t, auto& n) { one.touches.emplace_back(t["image"], n["offset"]); })) return false;
        } else if (*key == "timeline") {
            // [[ns, stack, context], ...]
            if (!r.eat('[')) return false;
            if (!r.eat(']')) {
                do {
                    if (!r.eat('[')) return false;
                    sample_at at;
                    auto a = r.number(); r.eat(','); auto b = r.number(); r.eat(','); auto c = r.number();
                    if (!a || !b || !r.eat(']')) return false;
                    at.ns = *a; at.stack = *b; at.context = c ? *c : 0;
                    one.timeline.push_back(at);
                } while (r.eat(','));
                if (!r.eat(']')) return false;
            }
        }
        else r.skip_value();
    } while (r.eat(','));
    into.programs.push_back(std::move(one));
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

// --- the forms of a report beside the summary -----------------------------------------

// Folded stacks: `outer;...;inner count', one a line.
int flame(const report& r) {
    for (auto const& [stack, count] : r.folded) std::println("{} {}", stack, count);
    return r.folded.empty() ? 1 : 0;
}

std::string json_text(const std::string& s) {
    std::string o = "\"";
    for (char c : s) {
        if (c == '"' || c == '\\') { o += '\\'; o += c; }
        else if (static_cast<unsigned char>(c) < 0x20) o += '?';
        else o += c;
    }
    return o + "\"";
}

// The Trace Event Format, which Perfetto and chrome://tracing read: each program a
// process, its start's moments as spans one after another, each sample an
// instant on its context's row, all on the monotonic clock the reports share.
int trace(const report& r) {
    std::uint64_t first = ~0ull;
    for (auto const& p : r.programs) if (p.started_ns && p.started_ns < first) first = p.started_ns;
    if (first == ~0ull) first = 0;
    std::println("{{\"traceEvents\": [");
    bool any = false;
    auto event = [&](const std::string& e) { std::print("{}  {}", any ? ",\n" : "", e); any = true; };
    for (auto const& p : r.programs) {
        const double base = static_cast<double>(p.started_ns - first) / 1000.0;
        event(std::format("{{\"name\": \"process_name\", \"ph\": \"M\", \"pid\": {}, \"args\": {{\"name\": {}}}}}",
                          p.id, json_text(std::filesystem::path(p.image).filename().string() + " " + std::to_string(p.id))));
        std::uint64_t from = 0;
        for (auto const& m : p.moments) {
            event(std::format("{{\"name\": {}, \"ph\": \"X\", \"pid\": {}, \"tid\": 0, \"ts\": {:.3f}, \"dur\": {:.3f}, \"args\": {{\"faults\": {}}}}}",
                              json_text("to " + m.name), p.id, base + static_cast<double>(from) / 1000.0,
                              static_cast<double>(m.ns - from) / 1000.0, m.faults));
            from = m.ns;
        }
        for (auto const& s : p.timeline) {
            const std::string& stack = s.stack < p.stacks.size() ? p.stacks[s.stack] : std::string("?");
            const auto leaf = stack.substr(stack.rfind(';') == std::string::npos ? 0 : stack.rfind(';') + 1);
            event(std::format("{{\"name\": {}, \"ph\": \"i\", \"s\": \"t\", \"pid\": {}, \"tid\": {}, \"ts\": {:.3f}, \"args\": {{\"stack\": {}}}}}",
                              json_text(leaf), p.id, s.context, base + static_cast<double>(s.ns) / 1000.0, json_text(stack)));
        }
    }
    std::println("\n]}}");
    return 0;
}

std::optional<std::vector<unsigned char>> read_bytes(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) return std::nullopt;
    return std::vector<unsigned char>((std::istreambuf_iterator<char>(in)), {});
}

// A symbol ordering file: the image's functions whose pages its start executed,
// in the order it first executed them, each once; within a page, in address
// order.
int order(const std::string& image_path, const report& r) {
    auto image = read_bytes(image_path);
    if (!image) { std::println(std::cerr, "okprof: {} cannot be read", image_path); return 2; }
    struct sym { std::uint64_t value, size; std::string name; };
    std::vector<sym> syms;
    okld_symbols(image->data(), image->size(), [](okld_u64 v, okld_u64 n, const char* name, void* c) {
        static_cast<std::vector<sym>*>(c)->push_back({ v, n, name });
    }, &syms);
    std::ranges::sort(syms, [](const sym& a, const sym& b) { return a.value < b.value; });
    // The file offset of a page to the address of the image: its segment.
    struct seg { std::uint64_t offset, vaddr, filesz; };
    std::vector<seg> segs;
    {
        const auto* b = image->data();
        std::uint64_t phoff = 0; std::uint16_t phnum = 0;
        std::memcpy(&phoff, b + 32, 8); std::memcpy(&phnum, b + 56, 2);
        for (unsigned i = 0; i < phnum; ++i) {
            std::uint32_t type = 0; std::uint64_t off = 0, va = 0, fs = 0;
            const auto* ph = b + phoff + i * 56;
            std::memcpy(&type, ph, 4); std::memcpy(&off, ph + 8, 8); std::memcpy(&va, ph + 16, 8); std::memcpy(&fs, ph + 32, 8);
            if (type == 1) segs.push_back({ off, va, fs });
        }
    }
    // The touches of the image by its file's name; where no report names it so
    // (the image measured was installed under another), those of the image each
    // report ran.
    const auto stem = std::filesystem::path(image_path).filename().string();
    auto named = [&](const std::string& path) { return std::filesystem::path(path).filename().string() == stem; };
    bool by_name = false;
    for (auto const& p : r.programs)
        for (auto const& t : p.touches) by_name = by_name || named(t.first);
    std::set<std::string> given;
    std::uint64_t pages = 0;
    for (auto const& p : r.programs)
        for (auto const& [img, offset] : p.touches) {
            if (by_name ? !named(img) : img != p.image) continue;
            ++pages;
            for (auto const& s : segs) {
                if (offset < s.offset || offset >= s.offset + s.filesz) continue;
                const std::uint64_t lo = s.vaddr + (offset - s.offset), hi = lo + p.page;
                auto it = std::ranges::lower_bound(syms, lo, {}, [](const sym& x) { return x.value + (x.size ? x.size : 1); });
                for (; it != syms.end() && it->value < hi; ++it)
                    if (given.insert(it->name).second) std::println("{}", it->name);
            }
        }
    if (pages == 0) { std::println(std::cerr, "okprof: the reports record no touch of {}", stem); return 1; }
    return 0;
}

// The names reached through each directory a program was granted (`record
// --what names'): the records, `<kind><name>\0' each, by directory.
int names(const std::string& dir) {
    std::map<std::string, std::array<std::uint64_t, 5>> by;   // r w s a l
    std::uint64_t ended = 0, records = 0;
    std::error_code ec;
    for (auto const& e : std::filesystem::directory_iterator(dir, ec)) {
        if (e.path().extension() != ".record") continue;
        ++records;
        auto bytes = read_bytes(e.path().string());
        if (!bytes) continue;
        std::string root;
        if (std::ifstream named(e.path().string() + ".root"); named) std::getline(named, root);
        std::size_t at = 0;
        while (at < bytes->size()) {
            const std::size_t end = std::find(bytes->begin() + static_cast<std::ptrdiff_t>(at), bytes->end(), '\0') - bytes->begin();
            if (end >= bytes->size() || end == at) break;
            const char kind = static_cast<char>((*bytes)[at]);
            const std::string name(reinterpret_cast<const char*>(bytes->data()) + at + 1, end - at - 1);
            at = end + 1;
            if (kind == 'e') { ++ended; continue; }
            const auto slash = name.rfind('/');
            const std::string where = root + (root.ends_with("/") || root.empty() ? "" : "/") + (slash == std::string::npos ? "" : name.substr(0, slash));
            const int k = kind == 'r' ? 0 : kind == 'w' ? 1 : kind == 's' ? 2 : kind == 'a' ? 3 : kind == 'l' ? 4 : -1;
            if (k >= 0) ++by[where][static_cast<std::size_t>(k)];
        }
    }
    if (records == 0) { std::println(std::cerr, "okprof: {} holds no record", dir); return 2; }
    std::vector<std::pair<std::string, std::array<std::uint64_t, 5>>> rows(by.begin(), by.end());
    std::ranges::sort(rows, [](auto const& a, auto const& b) { return a.second[3] > b.second[3]; });
    std::println("{} record{}, {} program end{} written", records, records == 1 ? "" : "s", ended, ended == 1 ? "" : "s");
    std::println("{:>9} {:>9} {:>9} {:>9} {:>9}  directory", "absent", "present", "read", "written", "listed");
    for (auto const& [where, n] : rows)
        std::println("{:>9} {:>9} {:>9} {:>9} {:>9}  {}", n[3], n[2], n[0], n[1], n[4], where.empty() ? "." : where);
    return 0;
}

int report_cmd(std::vector<std::string> args) {
    std::string form, image;
    while (!args.empty() && args.front().starts_with("--")) {
        if (args.front() == "--flame") form = "flame";
        else if (args.front() == "--format=trace") form = "trace";
        else if (args.front() == "--order" && args.size() > 1) { form = "order"; image = args[1]; args.erase(args.begin()); }
        else if (args.front() == "--names" && args.size() > 1) return names(args[1]);
        else { std::println(std::cerr, "okprof report: unknown option {}", args.front()); return 2; }
        args.erase(args.begin());
    }
    report r;
    if (!read_reports(args, r)) return 2;
    if (form == "flame") return flame(r);
    if (form == "trace") return trace(r);
    if (form == "order") return order(image, r);
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
    for (auto const& p : r.programs) {
        if (p.moments.empty()) continue;
        std::println("\nthe start of {} ({}), to each moment", std::filesystem::path(p.image).filename().string(), p.id);
        std::uint64_t ns = 0, faults = 0;
        for (auto const& m : p.moments) {
            std::println("  {:<14} {:>12}  {:>8} faults  (+{}, +{})", m.name, ms(m.ns), m.faults, ms(m.ns - ns), m.faults - faults);
            ns = m.ns; faults = m.faults;
        }
    }
    if (!r.folded.empty()) {
        std::map<std::string, std::uint64_t> leaves;
        std::uint64_t all = 0;
        for (auto const& [stack, count] : r.folded) {
            const auto cut = stack.rfind(';');
            leaves[cut == std::string::npos ? stack : stack.substr(cut + 1)] += count;
            all += count;
        }
        std::vector<std::pair<std::string, std::uint64_t>> top(leaves.begin(), leaves.end());
        std::ranges::sort(top, [](auto const& a, auto const& b) { return a.second > b.second; });
        std::println("\nwhere the samples fell ({} in all; `--flame' gives the stacks)", all);
        for (std::size_t i = 0; i < top.size() && i < 20; ++i)
            std::println("  {:>6.2f}%  {}", 100.0 * static_cast<double>(top[i].second) / static_cast<double>(all), top[i].first);
    }
    for (auto const& p : r.programs)
        if (!p.touches.empty())
            std::println("\n{} pages of {} executed first by its start (`--order <image>', `okld touch')",
                         p.touches.size(), std::filesystem::path(p.image).filename().string());
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

// The directories this program was given, each granted to the program started,
// under its own name and recorded (`names', openkal 0.23): a record of each,
// `<dir>/<n>.record', with the name it was granted under beside it.
struct recorded_grants {
    std::vector<kal_preopen> grants;
    std::vector<std::string> names;
    std::vector<kal_file> records;
    std::vector<kal_dir> dirs;      // the records' directory, and each granted one
    std::vector<kal_dir> granted;
    ~recorded_grants() {
        for (auto d : granted) kal_fs_close_dir(d);
        for (auto d : dirs) kal_fs_close_dir(d);
        for (auto f : records) kal_fs_close_file(f);
    }
};

bool grant_recorded(const std::string& dir, recorded_grants& out) {
    kal_dir into{}; std::string rest;
    std::error_code ec;
    const auto absolute = std::filesystem::absolute(dir, ec).generic_string();
    if (!locate(absolute, into, rest)) return false;
    kal_dir d{};
    if (kal_fs_open_dir(into, rest.c_str(), rest.size(), &d) != kal_ok) return false;
    out.dirs.push_back(d);
    const kal_uintptr n = kal_fs_preopen_count();
    out.names.reserve(n);
    for (kal_uintptr i = 0; i < n; ++i) {
        kal_dir pre{}; char name[1024]; kal_uintptr len = 0;
        if (kal_fs_preopen(i, &pre, name, sizeof name, &len) != kal_ok || len >= sizeof name) continue;
        if ((kal_fs_props(pre) & KAL_FS_PROP_ATTENUATE) == 0) {
            std::println(std::cerr, "okprof: this system's directories are not attenuated; names are not recorded");
            return false;
        }
        const std::string file = std::format("{}.record", i);
        kal_file rec{};
        if (kal_fs_open(d, file.c_str(), file.size(), KAL_OPEN_WRITE | KAL_OPEN_CREATE | KAL_OPEN_TRUNCATE, &rec) != kal_ok)
            return false;
        out.records.push_back(rec);
        if (std::ofstream root(absolute + "/" + file + ".root"); root) root << std::string_view(name, len) << "\n";
        kal_dir_rights rights{};
        rights.self_size = sizeof rights;
        rights.flags = KAL_DIR_RECORDED;
        rights.record = rec;
        kal_dir granted{};
        if (kal_fs_dir_attenuate(pre, &rights, &granted) != kal_ok) return false;
        out.granted.push_back(granted);
        out.names.emplace_back(name, len);
    }
    for (std::size_t i = 0; i < out.names.size(); ++i)
        out.grants.push_back(kal_preopen{ out.granted[i], out.names[i].c_str(), out.names[i].size() });
    return !out.grants.empty();
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

    // `names' is this program's to take, by the directories it grants; the rest
    // is the runner's.
    bool record_names = false;
    std::string runner_what;
    for (auto part : std::views::split(std::string_view(what), ',')) {
        const std::string one(part.begin(), part.end());
        if (one == "names") { record_names = true; continue; }
        if (!one.empty()) runner_what += (runner_what.empty() ? "" : ",") + one;
    }
    recorded_grants grants;
    if (record_names && !grant_recorded(dir, grants)) {
        std::println(std::cerr, "okprof: the directories could not be granted recorded");
        return 2;
    }
    // The environment, with OKRUN_PROF stated (replacing any it had).
    const std::string spec = std::format("OKRUN_PROF={}:{}", runner_what, std::filesystem::absolute(dir, ec).generic_string());
    std::vector<std::string> env;
    for (kal_uintptr i = 0; i < kal_env_var_count(); ++i) {
        char entry[16384];
        const kal_intptr n = kal_env_var_at(i, entry, sizeof entry);
        if (n <= 0 || n >= static_cast<kal_intptr>(sizeof entry)) continue;
        std::string e(entry, static_cast<std::size_t>(n));
        if (e.starts_with("OKRUN_PROF=")) continue;
        env.push_back(std::move(e));
    }
    if (!runner_what.empty()) env.push_back(spec);
    std::vector<const char*> argv, envp;
    std::vector<kal_uintptr> argl, envl;
    for (auto const& a : args) { argv.push_back(a.c_str()); argl.push_back(a.size()); }
    for (auto const& e : env) { envp.push_back(e.c_str()); envl.push_back(e.size()); }
    kal_dir work{};
    {
        char name[8]; kal_uintptr len = 0;
        kal_fs_preopen(0, &work, name, sizeof name, &len);
    }
    const kal_spawn how{ base, work, nullptr, record_names ? grants.grants.data() : nullptr,
                         record_names ? grants.grants.size() : 0, 0 };
    const kal_spawn_streams streams{ 0, 0, 0 };
    kal_process child{};
    const int e = kal_process_spawn(&how, rest.c_str(), rest.size(), argv.data(), argl.data(), argv.size(),
                                    envp.data(), envl.data(), envp.size(), &streams, &child);
    if (e != kal_ok) { std::println(std::cerr, "okprof: {} could not be started ({})", *program, e); return 2; }
    int status = 0, terminated = 0;
    kal_process_wait(child, &status, &terminated);
    kal_process_close(child);
    std::println(std::cerr, "okprof: the reports are in {}; `okprof report {}{}' reads them", dir,
                 record_names ? "--names " : "", dir);
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
    if (command == "report") return report_cmd(std::move(args));
    if (command == "diff") return diff_cmd(args);
    std::println(std::cerr, "okprof: unknown command {}", command);
    return 2;
}
