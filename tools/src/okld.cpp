// okld --- the ok format's tool on a build machine.
//
//   okld check <image> [--with <image it needs>]...
//                                  the convention (SPEC 12.2, 12.4); one line per violation
//   okld note <image>              the interfaces the image's imports require, written into
//                                  its requirements note
//   okld sign <image> <seed-file>  the signature note filled (Ed25519); prints the key
//   okld keygen <seed-file>        a new seed, written; prints its public key
//   okld inspect <image>           what the image is
//   okld note-source               the assembly that lays down the two notes, for the link
//   okld bundle <out.okb> [--name <n>] [--version <v>] [--entry <image>] [--sign <seed-file>] <image>...
//                                  an okb (docs/okb.md): the images, by architecture, and
//                                  okb.json; with --sign, each image and okb.json signed
//   okld bundle check <file.okb> [--require-signature] [--trust <hex>]...
//                                  every member stored, every image aligned, every digest,
//                                  signature and image of the okb; one line per violation
//
// It does not link: an image is linked by an ordinary linker (`ld.lld -shared').
import std;
import openkal.ld;
import openkal.run;

namespace {

const std::set<std::string>& surface() {
    static const std::set<std::string> names = [] {
        // The specification's surface, as libokrun binds it (generated from
        // SURFACE.txt by openkal-run's build.mcpp).
        std::set<std::string> s;
        unsigned long n = 0;
        const char* const* names = okrun_names(&n);
        for (unsigned long i = 0; i < n; ++i) s.insert(names[i]);
        return s;
    }();
    return names;
}

std::optional<std::vector<unsigned char>> read_file(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) return std::nullopt;
    return std::vector<unsigned char>((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
}

bool write_file(const std::string& path, const std::vector<unsigned char>& bytes) {
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    out.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    return static_cast<bool>(out);
}

std::string hex(const unsigned char* p, std::size_t n) {
    std::string s;
    for (std::size_t i = 0; i < n; ++i) s += std::format("{:02x}", p[i]);
    return s;
}

std::string interfaces(okld_u64 bits) {
    static const char* const names[] = { "abort", "stream", "memory", "env", "time", "random", "fs", "process",
                                         "task", "exec", "terminal", "net", "datagram", "space", "timeout" };
    std::string s;
    for (int b = 0; b < 15; ++b) if (bits & (1ull << b)) { if (!s.empty()) s += ' '; s += "openkal."; s += names[b]; }
    return s.empty() ? "none" : s;
}

// The names the images given with `--with' export.
std::set<std::string> g_elsewhere;

int check(const std::vector<unsigned char>& image) {
    int failures = okld_check(image.data(), image.size(),
        [](const char* n, void*) { return surface().contains(n) ? 1 : 0; },
        [](const char* n, void*) { return g_elsewhere.contains(n) ? 1 : 0; },
        [](const char* s, void*) { std::println(std::cerr, "okld: {}", s); }, nullptr);
    return failures == 0 ? 0 : 1;
}

// --- okb (docs/okb.md) ---------------------------------------------------------

std::string json_string(std::string_view v) {
    std::string out = "\"";
    for (char c : v) {
        switch (c) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n"; break;
            case '\t': out += "\\t"; break;
            default:
                if (static_cast<unsigned char>(c) < 0x20) out += std::format("\\u{:04x}", static_cast<unsigned>(c));
                else out += c;
        }
    }
    return out + "\"";
}

// --- JSON, as mcpp writes `mcpp-package.json_value' (mcpp SPEC-014 §4.5) ------------

struct json_value {
    enum kind_t { null, boolean, number, string, array, object } kind = null;
    bool b = false;
    double n = 0;
    std::string s;
    std::vector<json_value> items;
    std::map<std::string, json_value> fields;
    const json_value* get(std::string_view k) const {
        auto it = fields.find(std::string(k));
        return it == fields.end() ? nullptr : &it->second;
    }
    std::string str(std::string_view k) const {
        const json_value* v = get(k);
        return v && v->kind == string ? v->s : std::string();
    }
};

struct json_reader {
    std::string_view t;
    std::size_t at = 0;
    void ws() { while (at < t.size() && std::isspace(static_cast<unsigned char>(t[at]))) ++at; }
    bool text(std::string& out) {
        if (at >= t.size() || t[at] != '"') return false;
        ++at;
        while (at < t.size() && t[at] != '"') {
            char c = t[at++];
            if (c == '\\' && at < t.size()) {
                const char e = t[at++];
                switch (e) {
                    case 'n': c = '\n'; break; case 't': c = '\t'; break; case 'r': c = '\r'; break;
                    case 'b': c = '\b'; break; case 'f': c = '\f'; break;
                    case 'u': {
                        if (at + 4 > t.size()) return false;
                        const unsigned v = static_cast<unsigned>(std::stoul(std::string(t.substr(at, 4)), nullptr, 16));
                        at += 4;
                        if (v < 0x80) { out += static_cast<char>(v); continue; }
                        if (v < 0x800) { out += static_cast<char>(0xc0 | (v >> 6)); out += static_cast<char>(0x80 | (v & 0x3f)); continue; }
                        out += static_cast<char>(0xe0 | (v >> 12)); out += static_cast<char>(0x80 | ((v >> 6) & 0x3f));
                        out += static_cast<char>(0x80 | (v & 0x3f));
                        continue;
                    }
                    default: c = e;
                }
            }
            out += c;
        }
        if (at >= t.size()) return false;
        ++at;
        return true;
    }
    bool value(json_value& v, int depth = 0) {
        ws();
        if (at >= t.size() || depth > 64) return false;
        const char c = t[at];
        if (c == '{') {
            v.kind = json_value::object; ++at; ws();
            if (at < t.size() && t[at] == '}') { ++at; return true; }
            for (;;) {
                ws();
                std::string k;
                if (!text(k)) return false;
                ws();
                if (at >= t.size() || t[at] != ':') return false;
                ++at;
                if (!value(v.fields[k], depth + 1)) return false;
                ws();
                if (at < t.size() && t[at] == ',') { ++at; continue; }
                if (at < t.size() && t[at] == '}') { ++at; return true; }
                return false;
            }
        }
        if (c == '[') {
            v.kind = json_value::array; ++at; ws();
            if (at < t.size() && t[at] == ']') { ++at; return true; }
            for (;;) {
                v.items.emplace_back();
                if (!value(v.items.back(), depth + 1)) return false;
                ws();
                if (at < t.size() && t[at] == ',') { ++at; continue; }
                if (at < t.size() && t[at] == ']') { ++at; return true; }
                return false;
            }
        }
        if (c == '"') { v.kind = json_value::string; return text(v.s); }
        if (t.substr(at, 4) == "true") { v.kind = json_value::boolean; v.b = true; at += 4; return true; }
        if (t.substr(at, 5) == "false") { v.kind = json_value::boolean; at += 5; return true; }
        if (t.substr(at, 4) == "null") { at += 4; return true; }
        const std::size_t from = at;
        while (at < t.size() && (std::isdigit(static_cast<unsigned char>(t[at])) || std::string_view("+-.eE").contains(t[at]))) ++at;
        if (at == from) return false;
        v.kind = json_value::number;
        std::from_chars(t.data() + from, t.data() + at, v.n);
        return true;
    }
};

std::string base_name(const std::string& path) {
    const auto at = path.find_last_of("/\\");
    return at == std::string::npos ? path : path.substr(at + 1);
}

int bundle(const std::vector<std::string>& args) {
    // okld bundle <out.okb> [--name <n>] [--version <v>] [--entry <image>] [--sign <seed-file>] <image>...
    // okld bundle <out.okb> --package <staged-tree> [--sign <seed-file>]
    const char* usage = "usage: okld bundle <out.okb> [--name <n>] [--version <v>] [--entry <image>] [--sign <seed-file>] <image>...\n"
                        "       okld bundle <out.okb> --package <staged-tree> [--sign <seed-file>]";
    if (args.size() < 3) { std::println(std::cerr, "{}", usage); return 2; }
    const std::string out = args[1];
    std::string name, version, entry, seed_file, package;
    std::vector<std::string> paths;
    std::map<std::string, std::string> expected_arch;    // path -> the architecture its place names
    std::map<std::string, std::string> stated_digest;    // path -> the sha256 mcpp-package.json states
    std::map<std::string, std::string> arch_entry;       // architecture -> its entry's file name
    for (std::size_t i = 2; i < args.size(); ++i) {
        const auto& a = args[i];
        auto value = [&](std::string& into) {
            if (i + 1 >= args.size()) { std::println(std::cerr, "okld: {} needs a value", a); return false; }
            into = args[++i];
            return true;
        };
        if (a == "--name") { if (!value(name)) return 2; }
        else if (a == "--version") { if (!value(version)) return 2; }
        else if (a == "--entry") { if (!value(entry)) return 2; }
        else if (a == "--sign") { if (!value(seed_file)) return 2; }
        else if (a == "--package") { if (!value(package)) return 2; }
        else if (a.starts_with("--")) { std::println(std::cerr, "okld: unknown option {}", a); return 2; }
        else paths.push_back(a);
    }
    if (!package.empty()) {
        // A PACKAGE MCPP STAGED (mcpp SPEC-014 §4.5): its images are the files
        // of role `image', at `lib/<arch>/<file>'; its entry per architecture
        // is `launch.entry'; its name and version are the package's. Every
        // other role (launcher, loader, resource, metadata) is not a member of
        // an okb of this version.
        if (!paths.empty() || !entry.empty()) { std::println(std::cerr, "okld: --package names the images and the entry; give neither beside it"); return 2; }
        const std::string at = (std::filesystem::path(package) / "mcpp-package.json").string();
        auto text = read_file(at);
        if (!text) { std::println(std::cerr, "okld: {} cannot be read; --package names a tree mcpp staged", at); return 1; }
        json_value doc;
        json_reader r{ std::string_view(reinterpret_cast<const char*>(text->data()), text->size()) };
        if (!r.value(doc) || doc.kind != json_value::object) { std::println(std::cerr, "okld: {} is not a JSON object", at); return 1; }
        const json_value* schema = doc.get("schema");
        if (!schema || schema->kind != json_value::number || schema->n != 1) { std::println(std::cerr, "okld: {}: schema {} is not the one this okld reads (1)", at, schema && schema->kind == json_value::number ? std::format("{}", schema->n) : std::string("(none)")); return 1; }
        if (name.empty()) name = doc.str("name");
        if (version.empty()) version = doc.str("version");
        const json_value* launch = doc.get("launch");
        const json_value* entries = launch ? launch->get("entry") : nullptr;
        if (!entries || entries->kind != json_value::object || entries->fields.empty()) { std::println(std::cerr, "okld: {}: no launch.entry; the package is not a universal package of images", at); return 1; }
        for (const auto& [arch, e] : entries->fields) {
            if (e.kind != json_value::string || !e.s.starts_with("lib/" + arch + "/")) { std::println(std::cerr, "okld: {}: launch.entry.{} is not lib/{}/<image>", at, arch, arch); return 1; }
            arch_entry[arch] = base_name(e.s);
        }
        const json_value* files = doc.get("files");
        if (!files || files->kind != json_value::array) { std::println(std::cerr, "okld: {}: no files", at); return 1; }
        for (const auto& f : files->items) {
            if (f.str("role") != "image") continue;
            const std::string rel = f.str("path");
            const auto slash = rel.find('/', 4);
            if (!rel.starts_with("lib/") || slash == std::string::npos || rel.find('/', slash + 1) != std::string::npos) {
                std::println(std::cerr, "okld: {}: the image {} is not at lib/<arch>/<file>", at, rel);
                return 1;
            }
            const std::string path = (std::filesystem::path(package) / rel).string();
            paths.push_back(path);
            expected_arch[path] = rel.substr(4, slash - 4);
            if (const auto d = f.str("sha256"); !d.empty()) stated_digest[path] = d;
        }
        if (paths.empty()) { std::println(std::cerr, "okld: {}: no file of role `image'", at); return 1; }
    }
    if (paths.empty()) { std::println(std::cerr, "okld: an okb holds at least one image"); return 2; }
    std::optional<std::vector<unsigned char>> seed;
    if (!seed_file.empty()) {
        seed = read_file(seed_file);
        if (!seed || seed->size() != 32) { std::println(std::cerr, "okld: {} is not a 32-byte seed", seed_file); return 1; }
    }

    // The images, by architecture and name: each one an image of the format,
    // noted, of an architecture the format fixes a convention for.
    struct image { std::string arch, file; std::vector<unsigned char> bytes; };
    std::map<std::string, image> members;   // "<arch>/<file>" -> image, in order
    for (const auto& path : paths) {
        auto bytes = read_file(path);
        if (!bytes) { std::println(std::cerr, "okld: {} cannot be read", path); return 1; }
        okld_info info{};
        okld_why why{};
        if (okld_read(bytes->data(), bytes->size(), &info, &why) != 0) { std::println(std::cerr, "okld: {}: {}", path, why.text); return 1; }
        if (!info.has_requirements) { std::println(std::cerr, "okld: {}: no requirements note; `okld note' it first", path); return 1; }
        const char* arch = okld_okb_arch_of(info.machine);
        if (!arch) { std::println(std::cerr, "okld: {}: an architecture okb has no directory for", path); return 1; }
        if (auto e = expected_arch.find(path); e != expected_arch.end() && e->second != arch) {
            std::println(std::cerr, "okld: {}: an image of {}, in the directory of {}", path, arch, e->second);
            return 1;
        }
        if (auto d = stated_digest.find(path); d != stated_digest.end()) {
            unsigned char have[32];
            okld_sha256(bytes->data(), bytes->size(), have);
            if (hex(have, 32) != d->second) { std::println(std::cerr, "okld: {}: its content is not the one mcpp-package.json states (sha256)", path); return 1; }
        }
        const auto file = base_name(path);
        if (!file.ends_with(".oke") && !file.ends_with(".okso")) { std::println(std::cerr, "okld: {}: an image is named <name>.oke or <name>.okso", path); return 1; }
        if (seed && okld_sign(bytes->data(), bytes->size(), seed->data(), &why) != 0) { std::println(std::cerr, "okld: {}: {}", path, why.text); return 1; }
        const auto key = std::format("{}/{}", arch, file);
        if (members.contains(key)) { std::println(std::cerr, "okld: two images are {}", key); return 1; }
        members[key] = image{ arch, file, std::move(*bytes) };
    }
    std::set<std::string> archs;
    for (const auto& [k, m] : members) archs.insert(m.arch);
    if (entry.empty() && !arch_entry.empty()) entry = arch_entry.begin()->second;
    if (entry.empty())
        for (const auto& [k, m] : members) if (m.file.ends_with(".oke")) { entry = m.file; break; }
    if (entry.empty()) { std::println(std::cerr, "okld: no .oke among the images, and no --entry"); return 1; }
    for (const auto& a : archs) {
        if (!arch_entry.contains(a)) arch_entry[a] = entry;
        if (!members.contains(a + "/" + arch_entry[a])) { std::println(std::cerr, "okld: the architecture {} has no {}", a, arch_entry[a]); return 1; }
    }
    for (const auto& [a, e] : arch_entry)
        if (!archs.contains(a)) { std::println(std::cerr, "okld: an entry is stated for {}, which has no image", a); return 1; }
    if (name.empty()) name = entry.substr(0, entry.rfind('.'));

    // okb.json: keys in a fixed order, files by member name.
    std::string json = std::format("{{\n  \"okb\": {},\n  \"name\": {},\n", okld::okb_version, json_string(name));
    if (!version.empty()) json += std::format("  \"version\": {},\n", json_string(version));
    json += std::format("  \"entry\": {},\n  \"architectures\": {{\n", json_string(entry));
    {
        std::size_t i = 0;
        for (const auto& a : archs)
            json += std::format("    {}: {{ \"dir\": {}, \"entry\": {} }}{}\n", json_string(a), json_string(a),
                                json_string(arch_entry[a]), ++i == archs.size() ? "" : ",");
    }
    json += "  },\n  \"files\": {\n";
    {
        std::size_t i = 0;
        for (const auto& [k, m] : members) {
            unsigned char d[32];
            okld_sha256(m.bytes.data(), m.bytes.size(), d);
            json += std::format("    {}: {{ \"sha256\": \"{}\", \"size\": {} }}{}\n", json_string(k), hex(d, 32),
                                m.bytes.size(), ++i == members.size() ? "" : ",");
        }
    }
    json += "  }\n}\n";

    std::array<unsigned char, 96> signature{};
    std::vector<okld_zip_input> in;
    in.push_back({ "okb.json", json.data(), json.size(), 0 });
    if (seed) {
        okld_public_key(seed->data(), signature.data());
        okld_sign_message(seed->data(), json.data(), json.size(), signature.data() + 32);
        in.push_back({ "okb.sig", signature.data(), signature.size(), 0 });
    }
    for (const auto& [k, m] : members) in.push_back({ k.c_str(), m.bytes.data(), m.bytes.size(), 1 });
    const okld_u64 need = okld_zip_write(in.data(), in.size(), okld::okb_alignment, nullptr, 0);
    std::vector<unsigned char> archive(need);
    okld_zip_write(in.data(), in.size(), okld::okb_alignment, archive.data(), archive.size());
    if (!write_file(out, archive)) { std::println(std::cerr, "okld: {} cannot be written", out); return 1; }
    std::println("{}: okb {}, {}, {} architecture(s), {} image(s){}, {} bytes", out, okld::okb_version, name,
                 archs.size(), members.size(), seed ? ", signed" : "", archive.size());
    return 0;
}

int bundle_check(const std::vector<std::string>& args) {
    // okld bundle check <file.okb> [--require-signature] [--trust <hex>]...
    if (args.size() < 3) { std::println(std::cerr, "usage: okld bundle check <file.okb> [--require-signature] [--trust <hex>]..."); return 2; }
    const std::string path = args[2];
    bool require = false;
    std::vector<std::array<unsigned char, 32>> trusted;
    for (std::size_t i = 3; i < args.size(); ++i) {
        if (args[i] == "--require-signature") { require = true; continue; }
        if (args[i] == "--trust" && i + 1 < args.size() && args[i + 1].size() == 64) {
            std::array<unsigned char, 32> k{};
            for (int b = 0; b < 32; ++b) k[b] = static_cast<unsigned char>(std::stoi(args[i + 1].substr(2 * b, 2), nullptr, 16));
            trusted.push_back(k);
            ++i;
            continue;
        }
        std::println(std::cerr, "okld: unknown option {}", args[i]);
        return 2;
    }
    if (!trusted.empty()) require = true;
    auto bytes = read_file(path);
    if (!bytes) { std::println(std::cerr, "okld: {} cannot be read", path); return 1; }
    const auto& a = *bytes;
    int failures = 0;
    auto fail = [&](std::string s) { std::println(std::cerr, "okld: {}: {}", path, s); ++failures; };
    auto is_trusted = [&](const unsigned char* k) {
        if (trusted.empty()) return true;
        for (const auto& t : trusted) if (std::equal(t.begin(), t.end(), k)) return true;
        return false;
    };

    // The members, as the central directory states them.
    std::vector<okld_zip_member> list;
    okld_why why{};
    if (okld_zip_each(a.data(), a.size(), [](const okld_zip_member* m, void* c) -> int {
            static_cast<std::vector<okld_zip_member>*>(c)->push_back(*m);
            return 0;
        }, &list, &why) != 0) {
        fail(why.text);
        return 1;
    }
    auto member_name = [](const okld_zip_member& m) { return std::string(m.name, m.name_len); };
    const okld_zip_member* json = nullptr;
    const okld_zip_member* sig = nullptr;
    for (const auto& m : list) {
        if (member_name(m) == "okb.json") json = &m;
        if (member_name(m) == "okb.sig") sig = &m;
        if (m.method != 0 || m.size != m.original) fail(std::format("{}: not stored", member_name(m)));
    }
    if (!json) { fail("no okb.json"); return 1; }
    if (okld_okb_admit(a.data(), a.size(), json, nullptr, 0, &why) != 0) { fail(why.text); return 1; }
    const auto* text = a.data() + json->data;
    okld_okb_manifest manifest{};
    if (okld_okb_read_manifest(text, json->size, &manifest, &why) != 0) { fail(why.text); return 1; }

    // The manifest's signature.
    if (sig) {
        if (sig->size != 96) fail("okb.sig is not 96 bytes (a key and a signature)");
        else if (okld_okb_admit(a.data(), a.size(), sig, nullptr, 0, &why) != 0) fail(why.text);
        else {
            const auto* k = a.data() + sig->data;
            if (okld_verify_message(k, text, json->size, k + 32) != 1) fail("the signature of okb.json does not hold");
            else if (!is_trusted(k)) fail(std::format("okb.json is signed by {}, which is not trusted", hex(k, 32)));
        }
    } else if (require) {
        fail("okb.json is not signed (no okb.sig), and a signature is required");
    }

    // Every stated file is a member, and every member but the manifest's own is stated.
    std::set<std::string> stated;
    okld_okb_each_file(text, json->size, [](const char* n, okld_size l, void* c) -> int {
        static_cast<std::set<std::string>*>(c)->insert(std::string(n, l));
        return 0;
    }, &stated);
    std::set<std::string> present;
    for (const auto& m : list) present.insert(member_name(m));
    for (const auto& f : stated) if (!present.contains(f)) fail(std::format("okb.json states {}, which the archive does not hold", f));

    // Each image: admitted (stored, aligned, its stated content), of its
    // directory's architecture, signed where asked, and following the
    // convention with the exports of its directory's other images.
    // An image refused here is still counted among its directory's exports,
    // so that one refusal is reported once and not again by each image that
    // needs it.
    std::map<std::string, std::vector<const okld_zip_member*>> by_dir;
    std::set<const okld_zip_member*> refused;
    for (const auto& m : list) {
        const auto n = member_name(m);
        if (n == "okb.json" || n == "okb.sig" || n.ends_with("/")) continue;
        if (okld_okb_admit(a.data(), a.size(), &m, text, json->size, &why) != 0) { fail(why.text); refused.insert(&m); }
        if (!okld_okb_is_image(n.data(), n.size())) continue;
        const auto slash = n.find('/');
        by_dir[slash == std::string::npos ? std::string() : n.substr(0, slash)].push_back(&m);
    }
    for (const auto& arch : std::span(manifest.archs, manifest.arch_count)) {
        const std::string entry = std::format("{}/{}", arch.dir, arch.entry);
        if (!present.contains(entry)) fail(std::format("the entry of {}, {}, is not a member", arch.name, entry));
    }
    for (const auto& [dir, images] : by_dir) {
        const okld_okb_arch* arch = nullptr;
        for (const auto& x : std::span(manifest.archs, manifest.arch_count)) if (dir == x.dir) arch = &x;
        g_elsewhere.clear();
        for (const auto* m : images)
            okld_exports(a.data() + m->data, m->size, [](const char* n, void*) { g_elsewhere.insert(n); }, nullptr);
        for (const auto* m : images) {
            if (refused.contains(m)) continue;
            const auto n = member_name(*m);
            const auto* image = a.data() + m->data;
            okld_info info{};
            if (okld_read(image, m->size, &info, &why) != 0) { fail(std::format("{}: {}", n, why.text)); continue; }
            const char* machine = okld_okb_arch_of(info.machine);
            if (!arch) fail(std::format("{}: in {}/, which okb.json names no architecture for", n, dir));
            else if (!machine || std::string_view(machine) != arch->name)
                fail(std::format("{}: an image of {}, in the directory of {}", n, machine ? machine : "another architecture", arch->name));
            unsigned char key[32];
            const int v = okld_verify(image, m->size, key);
            if (v < 0) fail(std::format("{}: its signature does not hold", n));
            else if (v == 0 && require) fail(std::format("{}: not signed, and a signature is required", n));
            else if (v == 1 && !is_trusted(key)) fail(std::format("{}: signed by {}, which is not trusted", n, hex(key, 32)));
            struct ctx { std::string* name; int* failures; const std::string* path; } c{ const_cast<std::string*>(&n), &failures, &path };
            okld_check(image, m->size,
                [](const char* x, void*) { return surface().contains(x) ? 1 : 0; },
                [](const char* x, void*) { return g_elsewhere.contains(x) ? 1 : 0; },
                [](const char* sentence, void* p) {
                    auto& c = *static_cast<ctx*>(p);
                    std::println(std::cerr, "okld: {}: {}: {}", *c.path, *c.name, sentence);
                    ++*c.failures;
                }, &c);
        }
    }
    if (failures == 0) {
        std::string archs_text;
        for (const auto& x : std::span(manifest.archs, manifest.arch_count))
            archs_text += std::format("{}{} ({} image(s))", archs_text.empty() ? "" : ", ", x.name, by_dir[x.dir].size());
        std::println("{}: okb {}, {}{}; {}; every member holds{}", path, manifest.okb, manifest.name,
                     manifest.version[0] ? std::format(" {}", manifest.version) : std::string(), archs_text,
                     sig ? ", signed" : "");
    }
    return failures == 0 ? 0 : 1;
}

}  // namespace

int main(int argc, char** argv) {
    const std::vector<std::string> args(argv + 1, argv + argc);
    auto usage = [] { std::println(std::cerr, "usage: okld check|note|inspect <image> | sign <image> <seed-file> | keygen <seed-file> | note-source | bundle <out.okb> <image>... | bundle check <file.okb>"); return 2; };
    if (args.empty()) return usage();
    const auto& verb = args[0];

    if (verb == "note-source") {
        std::print("{}",
            "# The two notes of an ok image (SPEC 12.4): requirements, written by `okld note',\n"
            "# and a signature, written by `okld sign' and all zero until then.\n"
            "\t.section .note.openkal,\"a\",@note\n"
            "\t.p2align 2\n"
            "\t.long 8, 16, 1\n\t.asciz \"OPENKAL\"\n\t.long 1, 0\n\t.quad 0\n"
            "\t.p2align 2\n"
            "\t.long 8, 96, 2\n\t.asciz \"OPENKAL\"\n\t.fill 96, 1, 0\n");
        return 0;
    }
    if (verb == "keygen" && args.size() == 2) {
        std::array<unsigned char, 32> seed{};
        std::random_device rd;
        for (auto& b : seed) b = static_cast<unsigned char>(rd());
        if (!write_file(args[1], std::vector<unsigned char>(seed.begin(), seed.end()))) return 1;
        unsigned char key[32];
        okld_public_key(seed.data(), key);
        std::println("{}", hex(key, 32));
        return 0;
    }
    if (verb == "bundle" && args.size() >= 2 && args[1] == "check") return bundle_check(args);
    if (verb == "bundle") return bundle(args);
    if (args.size() < 2) return usage();
    auto image = read_file(args[1]);
    if (!image) { std::println(std::cerr, "okld: {} cannot be read", args[1]); return 1; }

    if (verb == "check") {
        for (std::size_t i = 2; i + 1 < args.size(); i += 2) {
            if (args[i] != "--with") return usage();
            auto other = read_file(args[i + 1]);
            if (!other) { std::println(std::cerr, "okld: {} cannot be read", args[i + 1]); return 1; }
            okld_exports(other->data(), other->size(), [](const char* n, void*) { g_elsewhere.insert(n); }, nullptr);
        }
        return check(*image);
    }
    if (verb == "note") {
        okld_u64 bits = 0;
        okld_required_imports(image->data(), image->size(),
                              [](const char* n, void* c) { *static_cast<okld_u64*>(c) |= okld_interface_of(n); }, &bits);
        okld_why why{};
        if (okld_set_requirements(image->data(), image->size(), bits, &why) != 0) { std::println(std::cerr, "okld: {}", why.text); return 1; }
        if (!write_file(args[1], *image)) return 1;
        std::println("{}: requires {}", args[1], interfaces(bits));
        return 0;
    }
    if (verb == "sign" && args.size() == 3) {
        auto seed = read_file(args[2]);
        if (!seed || seed->size() != 32) { std::println(std::cerr, "okld: {} is not a 32-byte seed", args[2]); return 1; }
        okld_why why{};
        if (okld_sign(image->data(), image->size(), seed->data(), &why) != 0) { std::println(std::cerr, "okld: {}", why.text); return 1; }
        if (!write_file(args[1], *image)) return 1;
        unsigned char key[32];
        okld_public_key(seed->data(), key);
        std::println("{}: signed by {}", args[1], hex(key, 32));
        return 0;
    }
    if (verb == "inspect") {
        okld_info info{};
        okld_why why{};
        if (okld_read(image->data(), image->size(), &info, &why) != 0) { std::println(std::cerr, "okld: {}", why.text); return 1; }
        std::println("architecture  {}", info.machine == 62 ? "x86_64" : info.machine == 183 ? "aarch64" : "other");
        std::println("format        {}", info.has_requirements ? std::format("{}.{}", info.format_major, info.format_minor) : std::string("no requirements note"));
        std::println("requires      {}", interfaces(info.interfaces));
        unsigned char key[32];
        const int v = okld_verify(image->data(), image->size(), key);
        std::println("signature     {}", v == 1 ? "valid, by " + hex(key, 32) : v == 0 ? std::string("none") : std::string("PRESENT AND WRONG"));
        std::println("span          {:#x}", info.span);
        std::println("entry         {:#x}", info.entry);
        std::println("needs         {} image(s)", info.needed_count);
        std::vector<std::string> imports;
        okld_imports(image->data(), image->size(), [](const char* n, void* c) { static_cast<std::vector<std::string>*>(c)->push_back(n); }, &imports);
        std::println("imports       {}", imports.size());
        for (const auto& n : imports) std::println("  {}", n);
        return 0;
    }
    return usage();
}
