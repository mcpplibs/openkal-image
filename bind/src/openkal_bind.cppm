// mcpp.mcpplibs.openkal_bind --- a library published as an ok image (`.okso')
// and a C header, called from a program of any system (part 2 design §8).
//
// The library's own build.mcpp calls `bind':
//
//     import mcpp;
//     import mcpp.mcpplibs.openkal_bind;
//     int main() {
//         return mcpp::mcpplibs::openkal_bind::bind({
//             .header = "include/mathlib.h",
//             .image  = "lib/{arch}/libmathlib.okso",
//         });
//     }
//
// On an openkal target the image is linked as it is and placed beside the
// program. On every other target the plugin reads the header's prototypes
// with clang (its AST, as JSON), checks the boundary, and generates a C source
// that defines each function under its own name: the first call opens the image
// through libokrun (`okrun_open_library') and every call forwards through a
// pointer of the image's convention --- System V on x86-64, whatever the
// system's --- so the compiler converts the call. The image is placed beside
// the program. A consumer depends on the library and includes its header as it
// would any other.
//
// THE BOUNDARY IS CHECKED, AND REFUSED WHERE IT CANNOT HOLD:
//
//   - C only: the header is read as C17; a declaration of another language is
//     an error of clang's, reported as the refusal;
//   - no `long', `unsigned long', `long double', `wchar_t', or a type that is
//     one (`off_t', `clock_t', `wint_t', a typedef of the header's own): an
//     image is LP64 and a Windows program LLP64, so these differ in size;
//   - functions only: a variable the header declares is not reachable;
//   - every function prototyped, not variadic, and exported by the image;
//   - a callback (a function pointer a function takes) fully prototyped, not
//     returning a function pointer; on x86-64 Windows the plugin passes the
//     image a System V entry that calls the program's function (a pool of
//     sixteen per callback type), and refuses a function pointer that crosses
//     the other way or inside a structure.
//
// What is not checked, and is the library's to keep: memory is released by the
// side that allocated it (an interface creates and destroys in pairs), and no
// exception crosses.

module;
#include <cstdio>
#include <cstdlib>

export module mcpp.mcpplibs.openkal_bind;

import std;
import mcpp;

export namespace mcpp::mcpplibs::openkal_bind {

struct library {
    // The C header that states the interface, relative to the package root.
    std::string header;
    // The image, relative to the package root; `{arch}' is the target's
    // architecture (`x86_64', `aarch64').
    std::string image;
    // Directories the header's own `#include' lines are found in, relative
    // to the package root. The header's own directory is always one.
    std::vector<std::string> include_dirs = {};
    // The clang that reads the header (the build program's choice). Empty:
    // OPENKAL_BIND_CLANG, then the toolchain's C compiler when it is clang,
    // then the declared payload `xim:llvm'.
    std::string clang = {};
};

// 0 when the binding is configured (or a payload is being installed, after
// which the program runs again); 1 when the boundary is refused, with the
// reason reported. A build program returns it from `main'.
int bind(const library& lib);

}  // namespace mcpp::mcpplibs::openkal_bind

namespace mcpp::mcpplibs::openkal_bind::detail {

namespace fs = std::filesystem;

// --- JSON, as clang writes its AST: objects keep their order -----------------

struct value {
    enum kind_t { null, boolean, number, string, array, object } kind = null;
    bool b = false;
    double n = 0;
    std::string s;
    std::vector<value> items;
    std::vector<std::pair<std::string, value>> fields;

    const value* get(std::string_view key) const {
        for (const auto& [k, v] : fields) if (k == key) return &v;
        return nullptr;
    }
    std::string str(std::string_view key) const {
        const value* v = get(key);
        return v && v->kind == string ? v->s : std::string();
    }
    bool flag(std::string_view key) const {
        const value* v = get(key);
        return v && v->kind == boolean && v->b;
    }
};

struct parser {
    std::string_view t;
    std::size_t at = 0;
    std::string error;

    void ws() { while (at < t.size() && (t[at] == ' ' || t[at] == '\n' || t[at] == '\r' || t[at] == '\t')) ++at; }
    bool fail(std::string why) { if (error.empty()) error = std::format("{} at byte {}", why, at); return false; }

    bool str(std::string& out) {
        if (at >= t.size() || t[at] != '"') return fail("a string was expected");
        ++at;
        while (at < t.size() && t[at] != '"') {
            char c = t[at++];
            if (c != '\\') { out += c; continue; }
            if (at >= t.size()) return fail("an unterminated escape");
            const char e = t[at++];
            switch (e) {
                case 'n': out += '\n'; break; case 't': out += '\t'; break; case 'r': out += '\r'; break;
                case 'b': out += '\b'; break; case 'f': out += '\f'; break;
                case 'u': {
                    if (at + 4 > t.size()) return fail("a short \\u escape");
                    unsigned v = 0;
                    for (int i = 0; i < 4; ++i) {
                        const char h = t[at++];
                        v = v * 16 + static_cast<unsigned>(h >= '0' && h <= '9' ? h - '0' : (h | 0x20) - 'a' + 10);
                    }
                    if (v < 0x80) out += static_cast<char>(v);
                    else if (v < 0x800) { out += static_cast<char>(0xc0 | (v >> 6)); out += static_cast<char>(0x80 | (v & 0x3f)); }
                    else { out += static_cast<char>(0xe0 | (v >> 12)); out += static_cast<char>(0x80 | ((v >> 6) & 0x3f)); out += static_cast<char>(0x80 | (v & 0x3f)); }
                    break;
                }
                default: out += e;
            }
        }
        if (at >= t.size()) return fail("an unterminated string");
        ++at;
        return true;
    }

    bool parse(value& v, int depth = 0) {
        if (depth > 512) return fail("nesting deeper than 512");
        ws();
        if (at >= t.size()) return fail("the document ends early");
        const char c = t[at];
        if (c == '{') {
            v.kind = value::object;
            ++at; ws();
            if (at < t.size() && t[at] == '}') { ++at; return true; }
            for (;;) {
                ws();
                std::string k;
                if (!str(k)) return false;
                ws();
                if (at >= t.size() || t[at] != ':') return fail("':' was expected");
                ++at;
                value item;
                if (!parse(item, depth + 1)) return false;
                v.fields.emplace_back(std::move(k), std::move(item));
                ws();
                if (at < t.size() && t[at] == ',') { ++at; continue; }
                if (at < t.size() && t[at] == '}') { ++at; return true; }
                return fail("',' or '}' was expected");
            }
        }
        if (c == '[') {
            v.kind = value::array;
            ++at; ws();
            if (at < t.size() && t[at] == ']') { ++at; return true; }
            for (;;) {
                value item;
                if (!parse(item, depth + 1)) return false;
                v.items.push_back(std::move(item));
                ws();
                if (at < t.size() && t[at] == ',') { ++at; continue; }
                if (at < t.size() && t[at] == ']') { ++at; return true; }
                return fail("',' or ']' was expected");
            }
        }
        if (c == '"') { v.kind = value::string; return str(v.s); }
        if (t.substr(at, 4) == "true") { v.kind = value::boolean; v.b = true; at += 4; return true; }
        if (t.substr(at, 5) == "false") { v.kind = value::boolean; at += 5; return true; }
        if (t.substr(at, 4) == "null") { at += 4; return true; }
        const std::size_t from = at;
        while (at < t.size() && (std::isdigit(static_cast<unsigned char>(t[at])) || t[at] == '-' || t[at] == '+'
                                 || t[at] == '.' || t[at] == 'e' || t[at] == 'E')) ++at;
        if (at == from) return fail("a value was expected");
        v.kind = value::number;
        std::from_chars(t.data() + from, t.data() + at, v.n);
        return true;
    }
};

// --- what the header declares ---------------------------------------------------

struct param { std::string name, type; };

struct function {
    std::string name, type, ret;
    std::vector<param> params;
    bool variadic = false, prototyped = true;
    std::string file;
    long line = 0;
};

struct record { std::string name; std::vector<param> fields; };

struct declarations {
    std::vector<function> functions;
    std::vector<std::string> variables;
    std::map<std::string, std::string> typedefs;     // name -> the type it names
    std::map<std::string, std::string> typedef_records;   // name -> record id (an unnamed record)
    std::map<std::string, record> records_by_name;   // "struct x", "union x"
    std::map<std::string, record> records_by_id;
};

struct walker {
    std::string root;   // the package root, generic, with a trailing '/'
    std::string file;   // the file the last location named (clang writes it once, then omits it)
    long line = 0;
    declarations out;

    bool ours() const { return file.starts_with(root); }

    // A location: its file, when written, and its line.
    void location(const value& loc) {
        if (loc.kind != value::object) return;
        if (const value* s = loc.get("spellingLoc")) location(*s);
        if (const value* e = loc.get("expansionLoc")) location(*e);
        if (const value* f = loc.get("file"); f && f->kind == value::string)
            file = fs::path(f->s).lexically_normal().generic_string();
        if (const value* l = loc.get("line"); l && l->kind == value::number) line = static_cast<long>(l->n);
    }

    // Every location in a subtree, in the order clang wrote them, so that the
    // file stays the one in force.
    void track(const value& v) {
        if (v.kind == value::object) {
            for (const auto& [k, f] : v.fields) {
                if (k == "loc" || k == "begin" || k == "end") location(f);
                track(f);
            }
        } else if (v.kind == value::array) {
            for (const auto& i : v.items) track(i);
        }
    }

    static std::string qual(const value& node) {
        const value* t = node.get("type");
        return t ? t->str("qualType") : std::string();
    }

    static std::string record_id_in(const value& v) {
        if (v.kind == value::object) {
            if (const value* d = v.get("decl"); d && d->kind == value::object) {
                const std::string kind = d->str("kind");
                if (kind == "RecordDecl") return d->str("id");
            }
            for (const auto& [k, f] : v.fields) if (auto id = record_id_in(f); !id.empty()) return id;
        } else if (v.kind == value::array) {
            for (const auto& i : v.items) if (auto id = record_id_in(i); !id.empty()) return id;
        }
        return {};
    }

    void decl(const value& node) {
        const std::string kind = node.str("kind");
        if (const value* loc = node.get("loc")) location(*loc);
        const std::string here = file;
        const long here_line = line;
        if (const value* range = node.get("range")) track(*range);
        const bool mine = here.starts_with(root);
        if (kind == "FunctionDecl" && mine) {
            function f;
            f.name = node.str("name");
            f.type = qual(node);
            f.file = here;
            f.line = here_line;
            f.variadic = f.type.find("...") != std::string::npos;
            const bool inline_ = node.flag("inline");
            const bool static_ = node.str("storageClass") == "static";
            if (const value* inner = node.get("inner"))
                for (const auto& p : inner->items)
                    if (p.str("kind") == "ParmVarDecl") f.params.push_back({ p.str("name"), qual(p) });
            // `int f()' in C17 has no prototype: its type is written with empty
            // parentheses and it has no parameters.
            f.prototyped = !(f.params.empty() && f.type.ends_with("()"));
            if (!inline_ && !static_) out.functions.push_back(std::move(f));
        } else if (kind == "VarDecl" && mine) {
            if (node.str("storageClass") != "static") out.variables.push_back(node.str("name"));
        } else if (kind == "TypedefDecl" && mine) {
            const std::string name = node.str("name");
            const value* t = node.get("type");
            out.typedefs[name] = t ? (t->str("desugaredQualType").empty() ? t->str("qualType") : t->str("desugaredQualType")) : "";
            if (const value* inner = node.get("inner"))
                if (auto id = record_id_in(*inner); !id.empty()) out.typedef_records[name] = id;
        } else if (kind == "RecordDecl" && mine) {
            record r;
            r.name = node.str("name");
            const std::string tag = node.str("tagUsed");
            if (const value* inner = node.get("inner"))
                for (const auto& f : inner->items)
                    if (f.str("kind") == "FieldDecl") r.fields.push_back({ f.str("name"), qual(f) });
            if (!r.name.empty()) out.records_by_name[std::format("{} {}", tag.empty() ? "struct" : tag, r.name)] = r;
            out.records_by_id[node.str("id")] = std::move(r);
        }
        if (const value* inner = node.get("inner"))
            for (const auto& child : inner->items) {
                // Nested declarations (a record's fields) are walked for their
                // locations; their declarations were read above.
                if (kind == "RecordDecl" || kind == "FunctionDecl" || kind == "TypedefDecl") track(child);
                else decl(child);
            }
    }
};

// --- the types of the boundary --------------------------------------------------

std::vector<std::string> tokens(std::string_view s) {
    std::vector<std::string> out;
    for (std::size_t i = 0; i < s.size();) {
        const char c = s[i];
        if (std::isalpha(static_cast<unsigned char>(c)) || c == '_') {
            std::size_t j = i;
            while (j < s.size() && (std::isalnum(static_cast<unsigned char>(s[j])) || s[j] == '_')) ++j;
            out.emplace_back(s.substr(i, j - i));
            i = j;
        } else {
            if (!std::isspace(static_cast<unsigned char>(c))) out.emplace_back(1, c);
            ++i;
        }
    }
    return out;
}

// A type whose size differs between an image (LP64) and a Windows program
// (LLP64): the reason, or empty.
std::string width_of_concern(const declarations& d, std::string_view type, std::set<std::string>& seen) {
    const auto t = tokens(type);
    for (std::size_t i = 0; i < t.size(); ++i) {
        const auto& w = t[i];
        if (w == "wchar_t" || w == "wint_t") return std::format("`{}' (16 bits on Windows, 32 in an image)", w);
        if (w == "off_t" || w == "clock_t") return std::format("`{}' (a `long' on Windows: 32 bits, 64 in an image)", w);
        if (w == "long") {
            if (i + 1 < t.size() && t[i + 1] == "long") { ++i; continue; }
            if (i + 1 < t.size() && t[i + 1] == "double") return "`long double' (64 bits on Windows and AArch64 systems, 80 or 128 in an image)";
            return "`long' (32 bits on Windows, 64 in an image); write `int64_t' or `int32_t'";
        }
        if (w == "struct" || w == "union") {
            if (i + 1 < t.size()) {
                const std::string key = w + " " + t[i + 1];
                if (seen.insert(key).second)
                    if (auto r = d.records_by_name.find(key); r != d.records_by_name.end())
                        for (const auto& f : r->second.fields)
                            if (auto why = width_of_concern(d, f.type, seen); !why.empty())
                                return std::format("{}, in the field `{}' of `{}'", why, f.name, key);
            }
            continue;
        }
        if (auto td = d.typedefs.find(w); td != d.typedefs.end() && seen.insert(w).second) {
            if (auto why = width_of_concern(d, td->second, seen); !why.empty())
                return std::format("{}, through `{}'", why, w);
            if (auto rid = d.typedef_records.find(w); rid != d.typedef_records.end())
                if (auto r = d.records_by_id.find(rid->second); r != d.records_by_id.end())
                    for (const auto& f : r->second.fields)
                        if (auto why = width_of_concern(d, f.type, seen); !why.empty())
                            return std::format("{}, in the field `{}' of `{}'", why, f.name, w);
        }
    }
    return {};
}

// The type a name stands for when it is a typedef of the header's own, else
// the text itself.
std::string resolved(const declarations& d, std::string type) {
    for (int guard = 0; guard < 16; ++guard) {
        std::string t = type;
        while (!t.empty() && t.back() == ' ') t.pop_back();
        auto td = d.typedefs.find(t);
        if (td == d.typedefs.end()) break;
        type = td->second;
    }
    return type;
}

// A pointer to a function: `R (*)(P...)'. The return type and the
// parameters' types, split at the top level.
struct signature { std::string ret; std::vector<std::string> params; bool prototyped = true, variadic = false; };

std::optional<signature> function_pointer(std::string_view type) {
    const auto star = type.find("(*)(");
    if (star == std::string_view::npos) return std::nullopt;
    signature s;
    s.ret = std::string(type.substr(0, star));
    while (!s.ret.empty() && s.ret.back() == ' ') s.ret.pop_back();
    std::string_view rest = type.substr(star + 3);   // "(P...)"
    if (rest.size() < 2 || rest.front() != '(' || rest.back() != ')') return std::nullopt;
    rest = rest.substr(1, rest.size() - 2);
    if (rest.empty()) { s.prototyped = false; return s; }
    int depth = 0;
    std::string cur;
    for (char c : rest) {
        if (c == '(' || c == '[') ++depth;
        if (c == ')' || c == ']') --depth;
        if (c == ',' && depth == 0) { s.params.push_back(cur); cur.clear(); continue; }
        cur += c;
    }
    s.params.push_back(cur);
    for (auto& p : s.params) {
        while (!p.empty() && p.front() == ' ') p.erase(p.begin());
        while (!p.empty() && p.back() == ' ') p.pop_back();
    }
    if (s.params.size() == 1 && s.params[0] == "void") s.params.clear();
    if (!s.params.empty() && s.params.back() == "...") s.variadic = true;
    return s;
}

bool is_function_pointer(const declarations& d, const std::string& type) {
    return resolved(d, type).find("(*)(") != std::string::npos;
}

// --- the image's exports --------------------------------------------------------

std::optional<std::set<std::string>> exports_of(const fs::path& image) {
    std::ifstream in(image, std::ios::binary);
    if (!in) return std::nullopt;
    const std::vector<unsigned char> b((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    auto u16 = [&](std::size_t o) { return o + 2 <= b.size() ? std::uint16_t(b[o] | (b[o + 1] << 8)) : 0; };
    auto u32 = [&](std::size_t o) { return o + 4 <= b.size() ? std::uint32_t(u16(o) | (std::uint32_t(u16(o + 2)) << 16)) : 0u; };
    auto u64 = [&](std::size_t o) { return std::uint64_t(u32(o)) | (std::uint64_t(u32(o + 4)) << 32); };
    if (b.size() < 64 || b[0] != 0x7f || b[1] != 'E' || b[2] != 'L' || b[3] != 'F' || b[4] != 2) return std::nullopt;
    const std::uint64_t shoff = u64(0x28);
    const std::uint16_t shentsize = u16(0x3a), shnum = u16(0x3c);
    if (!shoff || shentsize != 64) return std::nullopt;
    std::set<std::string> out;
    for (std::uint16_t i = 0; i < shnum; ++i) {
        const std::size_t sh = shoff + std::size_t(i) * 64;
        if (u32(sh + 4) != 11) continue;   // SHT_DYNSYM
        const std::uint64_t off = u64(sh + 0x18), size = u64(sh + 0x20);
        const std::uint32_t link = u32(sh + 0x28);
        const std::size_t strsh = shoff + std::size_t(link) * 64;
        const std::uint64_t stroff = u64(strsh + 0x18), strsize = u64(strsh + 0x20);
        for (std::uint64_t s = off; s + 24 <= off + size && s + 24 <= b.size(); s += 24) {
            const std::uint32_t name = u32(s);
            const unsigned char info = b[s + 4];
            const std::uint16_t shndx = u16(s + 6);
            if (shndx == 0 || (info >> 4) == 0 || name >= strsize) continue;   // undefined or local
            std::string n;
            for (std::size_t k = stroff + name; k < b.size() && b[k]; ++k) n += static_cast<char>(b[k]);
            out.insert(n);
        }
    }
    return out;
}

// --- running clang ----------------------------------------------------------------

std::string quoted(const std::string& s) { return "\"" + s + "\""; }

bool windows_host() { return std::string_view(mcpp::host()).find("windows") != std::string_view::npos; }

int run(std::string cmd) {
    // cmd.exe removes one outer pair of quotes from a line that begins with one.
    if (windows_host()) cmd = "\"" + cmd + "\"";
    std::fflush(stdout);
    return std::system(cmd.c_str());
}

std::string read_text(const fs::path& p) {
    std::ifstream in(p, std::ios::binary);
    return { std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>() };
}

bool is_clang(const fs::path& p) {
    const auto n = p.filename().string();
    return n.find("clang") != std::string::npos;
}

// Where the clang comes from (SPEC-007 R6.5): the build program's choice, the
// variable, the toolchain's own, the declared payload. Empty and pending while
// the payload is being installed.
struct found { std::string program; bool pending = false; };

found find_clang(const library& lib) {
    if (!lib.clang.empty()) {
        mcpp::decision("tool:mcpp.mcpplibs.openkal_bind:clang", "choice", lib.clang.c_str());
        return { lib.clang };
    }
    if (const char* e = std::getenv("OPENKAL_BIND_CLANG"); e && *e) {
        mcpp::decision("tool:mcpp.mcpplibs.openkal_bind:clang", "env", e);
        return { e };
    }
    for (const char* role : { "cc", "cxx" }) {
        const std::string t = mcpp::tool(role);
        if (!t.empty() && is_clang(t)) {
            // The C driver beside a clang++ is the same compiler.
            fs::path c = t;
            if (std::string(role) == "cxx") {
                auto n = c.filename().string();
                if (auto at = n.find("clang++"); at != std::string::npos) n.replace(at, 7, "clang");
                c = c.parent_path() / n;
            }
            mcpp::decision("tool:mcpp.mcpplibs.openkal_bind:clang", "choice", c.generic_string().c_str());
            return { c.generic_string() };
        }
    }
    const char* dir = mcpp::xpkg_request("xim", "llvm");
    if (mcpp::xpkg_pending()) return { {}, true };
    if (dir && *dir) {
        const fs::path c = fs::path(dir) / "bin" / (windows_host() ? "clang.exe" : "clang");
        mcpp::decision("tool:mcpp.mcpplibs.openkal_bind:clang", "payload", c.generic_string().c_str(), "", 0, "xim:llvm");
        return { c.generic_string() };
    }
    return {};
}

// A refusal: the build program's error output, and its exit status.
void refuse(const std::string& what, const std::string& hint) {
    std::fprintf(stderr, "error: %s\n", what.c_str());
    if (!hint.empty()) std::fprintf(stderr, "       help: %s\n", hint.c_str());
    std::fflush(stderr);
}

std::string arch_of(std::string_view triple) {
    if (triple.starts_with("x86_64") || triple.starts_with("amd64")) return "x86_64";
    if (triple.starts_with("aarch64") || triple.starts_with("arm64")) return "aarch64";
    return {};
}

std::string replace_all(std::string s, std::string_view from, std::string_view to) {
    for (std::size_t at = 0; (at = s.find(from, at)) != std::string::npos; at += to.size()) s.replace(at, from.size(), to);
    return s;
}

// --- the binding ------------------------------------------------------------------

std::string generate(const declarations& d, const std::string& header_name, const std::string& image_name,
                     const std::string& library_label, bool sysv, bool thunks) {
    std::string o;
    const std::string abi = sysv ? "__attribute__((sysv_abi))" : "";
    o += std::format("/* Generated by mcpplibs.openkal-bind from {}: the exports of {},\n"
                     " * called from this system through libokrun. Do not edit. */\n", header_name, image_name);
    o += std::format("#include \"{}\"\n#include <okrun.h>\n#include <stdio.h>\n#include <stdlib.h>\n\n", header_name);
    o += "static struct okrun_library* okbind_library;\n\n";
    o += "static void* okbind_symbol(const char* name) {\n"
         "    struct okrun_library* lib = __atomic_load_n(&okbind_library, __ATOMIC_ACQUIRE);\n"
         "    if (!lib) {\n"
         "        char why[512];\n"
         "        struct okrun_options options = {0};\n";
    o += std::format("        struct okrun_library* opened = okrun_open_library(\"{}\", &options, why, sizeof why);\n", image_name);
    o += std::format("        if (!opened) {{ fprintf(stderr, \"{}: %s\\n\", why); abort(); }}\n", library_label);
    o += "        struct okrun_library* expected = 0;\n"
         "        if (__atomic_compare_exchange_n(&okbind_library, &expected, opened, 0, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) lib = opened;\n"
         "        else { okrun_close(opened); lib = expected; }\n"
         "    }\n"
         "    void* p = okrun_symbol(lib, name);\n";
    o += std::format("    if (!p) {{ fprintf(stderr, \"{}: {} does not export %s\\n\", name); abort(); }}\n", library_label, image_name);
    o += "    return p;\n}\n\n";

    // Callbacks: one pool of System V entries per callback type.
    std::map<std::string, int> pools;   // resolved callback type -> pool number
    auto pool_of = [&](const std::string& type) -> int {
        const std::string t = resolved(d, type);
        if (auto it = pools.find(t); it != pools.end()) return it->second;
        const int n = static_cast<int>(pools.size());
        pools[t] = n;
        const auto s = *function_pointer(t);
        o += std::format("/* {} */\ntypedef __typeof__({}) okbind_cb{}_native;\n", t, type, n);
        o += std::format("typedef __typeof__({}) okbind_cb{}_r;\n", s.ret, n);
        std::string params, args;
        for (std::size_t i = 0; i < s.params.size(); ++i) {
            o += std::format("typedef __typeof__({}) okbind_cb{}_p{};\n", s.params[i], n, i);
            params += std::format("{}okbind_cb{}_p{} a{}", i ? ", " : "", n, i, i);
            args += std::format("{}a{}", i ? ", " : "", i);
        }
        if (params.empty()) params = "void";
        o += std::format("static okbind_cb{}_native okbind_cb{}_slots[16];\n", n, n);
        for (int k = 0; k < 16; ++k)
            o += std::format("static okbind_cb{0}_r __attribute__((sysv_abi)) okbind_cb{0}_t{1}({2}) {{ {3}okbind_cb{0}_slots[{1}]({4}); }}\n",
                             n, k, params, s.ret == "void" ? "" : "return ", args);
        o += std::format("static void* const okbind_cb{}_entries[16] = {{", n);
        for (int k = 0; k < 16; ++k) o += std::format("{}(void*)okbind_cb{}_t{}", k ? ", " : " ", n, k);
        o += " };\n";
        o += std::format(
            "static okbind_cb{0}_native okbind_cb{0}_wrap(okbind_cb{0}_native f) {{\n"
            "    if (!f) return f;\n"
            "    for (int i = 0; i < 16; ++i) {{\n"
            "        okbind_cb{0}_native expected = 0;\n"
            "        if (__atomic_load_n(&okbind_cb{0}_slots[i], __ATOMIC_ACQUIRE) == f) return (okbind_cb{0}_native)okbind_cb{0}_entries[i];\n"
            "        if (__atomic_compare_exchange_n(&okbind_cb{0}_slots[i], &expected, f, 0, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE) || expected == f)\n"
            "            return (okbind_cb{0}_native)okbind_cb{0}_entries[i];\n"
            "    }}\n"
            "    fprintf(stderr, \"{1}: more than sixteen functions of the type {2} were given to the library\\n\");\n"
            "    abort();\n"
            "}}\n\n", n, library_label, replace_all(t, "\"", "'"));
        return n;
    };

    for (const auto& f : d.functions) {
        std::string params, args, types;
        for (std::size_t i = 0; i < f.params.size(); ++i) {
            const auto& p = f.params[i];
            o += std::format("typedef __typeof__({}) okbind_{}_p{};\n", p.type, f.name, i);
            params += std::format("{}okbind_{}_p{} a{}", i ? ", " : "", f.name, i, i);
            types += std::format("{}okbind_{}_p{}", i ? ", " : "", f.name, i);
            if (thunks && is_function_pointer(d, p.type)) {
                const int n = pool_of(p.type);
                args += std::format("{}okbind_cb{}_wrap(a{})", i ? ", " : "", n, i);
            } else {
                args += std::format("{}a{}", i ? ", " : "", i);
            }
        }
        if (params.empty()) { params = "void"; types = "void"; }
        o += std::format("typedef __typeof__({}) okbind_{}_r;\n", f.ret, f.name);
        o += std::format("typedef okbind_{0}_r ({1} *okbind_{0}_t)({2});\n", f.name, abi, types);
        o += std::format("okbind_{0}_r {0}({1}) {{\n", f.name, params);
        o += std::format("    okbind_{0}_t f = (okbind_{0}_t)__atomic_load_n(&okbind_{0}_entry, __ATOMIC_ACQUIRE);\n", f.name);
        o += std::format("    if (!f) {{ f = (okbind_{0}_t)okbind_symbol(\"{0}\"); __atomic_store_n(&okbind_{0}_entry, (void*)f, __ATOMIC_RELEASE); }}\n", f.name);
        o += std::format("    {}f({});\n}}\n\n", f.ret == "void" ? "" : "return ", args);
    }
    // The entries' slots, declared before the functions that use them.
    std::string slots;
    for (const auto& f : d.functions) slots += std::format("static void* okbind_{}_entry;\n", f.name);
    const auto at = o.find("static void* okbind_symbol");
    o.insert(at, slots + "\n");
    return o;
}

// The return type of a function type `R (P...)'.
std::optional<std::string> return_type(const std::string& type) {
    if (type.empty() || type.back() != ')') return std::nullopt;
    int depth = 0;
    for (std::size_t i = type.size(); i-- > 0;) {
        if (type[i] == ')') ++depth;
        if (type[i] == '(' && --depth == 0) {
            std::string r = type.substr(0, i);
            while (!r.empty() && r.back() == ' ') r.pop_back();
            if (r.find('(') != std::string::npos) return std::nullopt;   // a function pointer, written out
            return r;
        }
    }
    return std::nullopt;
}

}  // namespace mcpp::mcpplibs::openkal_bind::detail

namespace mcpp::mcpplibs::openkal_bind {

int bind(const library& lib) {
    using namespace detail;
    const fs::path root = mcpp::manifest_dir();
    const std::string os = mcpp::target_os();
    std::string arch = mcpp::target_arch();
    if (arch.empty()) arch = arch_of(mcpp::target());
    const std::string image_rel = replace_all(lib.image, "{arch}", arch);
    const fs::path image = (root / image_rel).lexically_normal();
    const fs::path header = (root / lib.header).lexically_normal();
    const std::string label = std::format("{}", mcpp::package_name());
    mcpp::rerun_if_changed(image.generic_string().c_str());
    mcpp::rerun_if_changed(header.generic_string().c_str());
    mcpp::rerun_if_env_changed("OPENKAL_BIND_CLANG");

    std::error_code ec;
    if (!fs::is_regular_file(image, ec)) {
        refuse(std::format("{}: the image {} is not there", label, image.generic_string()),
               std::format("build the library's image for {} (`mcpp build --target {}-openkal'), or name it with `image'", arch, arch));
        return 1;
    }

    // An openkal program links the image as it is, and finds it beside itself.
    if (os == "openkal") {
        mcpp::link_flag(image.generic_string().c_str());
        mcpp::deploy(image_rel.c_str(), ".");
        return 0;
    }
    if (arch != "x86_64" && arch != "aarch64") {
        refuse(std::format("{}: an image has no convention on {}", label, mcpp::target()), "bind on an x86-64 or AArch64 target");
        return 1;
    }
    const bool windows = os == "windows";
    const bool sysv = arch == "x86_64";
    const bool thunks = windows && arch == "x86_64";
    auto stem = fs::path(mcpp::tool("cc")).stem().string();
    for (auto& c : stem) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    if (windows && stem == "cl") {
        refuse(std::format("{}: MSVC's compiler cannot call the System V convention an x86-64 image uses", label),
               "build with the llvm toolchain (`mcpp toolchain default llvm@23.1.3'), whose clang converts the call");
        return 1;
    }

    // THE HEADER, READ AS THE IMAGE READS IT: C17 for the image's own target,
    // with the compiler's freestanding headers only.
    const found clang = find_clang(lib);
    if (clang.pending) return 0;
    if (clang.program.empty()) {
        refuse(std::format("{}: no clang to read {} with", label, lib.header),
               "name one (`.clang' in build.mcpp, or OPENKAL_BIND_CLANG), or build with the llvm toolchain");
        return 1;
    }
    const fs::path out = mcpp::out_dir();
    fs::create_directories(out, ec);
    const fs::path ast = out / "openkal-bind.ast.json", err = out / "openkal-bind.clang.txt";
    std::string cmd = std::format("{} --no-default-config -x c -std=c17 -ffreestanding -nostdlibinc -fsyntax-only -Xclang -ast-dump=json --target={}-unknown-none-elf",
                                  quoted(clang.program), arch);
    std::vector<fs::path> dirs{ header.parent_path() };
    for (const auto& d : lib.include_dirs) dirs.push_back((root / d).lexically_normal());
    for (const auto& d : dirs) cmd += " -I" + quoted(d.generic_string());
    cmd += " " + quoted(header.generic_string()) + " > " + quoted(ast.string()) + " 2> " + quoted(err.string());
    if (run(cmd) != 0) {
        refuse(std::format("{}: {} is not a C interface clang reads:\n{}", label, lib.header, read_text(err)),
               "the boundary is C (C17) with the freestanding headers: <stdint.h>, <stddef.h>, <stdbool.h>");
        return 1;
    }
    value tree;
    const std::string text = read_text(ast);
    parser p{ text };
    if (!p.parse(tree)) {
        refuse(std::format("{}: clang's description of {} cannot be read: {}", label, lib.header, p.error), "");
        return 1;
    }
    walker w;
    w.root = root.lexically_normal().generic_string();
    if (!w.root.ends_with('/')) w.root += '/';
    if (const value* inner = tree.get("inner"))
        for (const auto& node : inner->items) w.decl(node);
    declarations& d = w.out;

    // THE BOUNDARY.
    std::vector<std::string> problems;
    for (const auto& v : d.variables)
        problems.push_back(std::format("the variable `{}': an image's data is not reachable; export a function that returns it", v));
    std::optional<std::set<std::string>> exported = exports_of(image);
    if (!exported) mcpp::warning(std::format("{}: the exports of {} cannot be read; each function is looked up at its first call", label, image.filename().string()).c_str());
    for (auto& f : d.functions) {
        const std::string where = std::format("`{}' ({}:{})", f.name, fs::path(f.file).filename().string(), f.line);
        if (!f.prototyped) { problems.push_back(std::format("{} has no prototype; write its parameters, or `(void)'", where)); continue; }
        if (f.variadic) { problems.push_back(std::format("{} is variadic; a variable argument list does not cross the boundary", where)); continue; }
        auto ret = return_type(f.type);
        if (!ret) { problems.push_back(std::format("{} returns a function pointer written out; name its type with a typedef", where)); continue; }
        f.ret = *ret;
        std::set<std::string> seen;
        if (auto why = width_of_concern(d, f.ret, seen); !why.empty()) problems.push_back(std::format("{} returns {}", where, why));
        if (thunks && is_function_pointer(d, f.ret)) problems.push_back(std::format("{} returns a function pointer; on x86-64 Windows a program cannot call an image's function through it", where));
        for (const auto& p : f.params) {
            std::set<std::string> s2;
            const std::string pname = p.name.empty() ? std::string("a parameter") : std::format("`{}'", p.name);
            if (auto why = width_of_concern(d, p.type, s2); !why.empty()) problems.push_back(std::format("{} takes {} of {}", where, pname, why));
            if (is_function_pointer(d, p.type)) {
                const auto sig = function_pointer(resolved(d, p.type));
                if (!sig || !sig->prototyped) problems.push_back(std::format("{} takes {}, a callback without a prototype; write its parameters", where, pname));
                else if (sig->variadic) problems.push_back(std::format("{} takes {}, a variadic callback", where, pname));
                else if (sig->ret.find("(*") != std::string::npos || is_function_pointer(d, sig->ret)) problems.push_back(std::format("{} takes {}, a callback that returns a function pointer", where, pname));
                else if (os == "macos")
                    for (const auto& cp : sig->params)
                        for (const auto& tok : tokens(resolved(d, cp)))
                            if (tok == "char" || tok == "short" || tok == "_Bool" || tok == "bool" || tok == "int8_t" || tok == "uint8_t" || tok == "int16_t" || tok == "uint16_t") {
                                problems.push_back(std::format("{} takes {}, a callback with a parameter narrower than 32 bits (`{}'), which the image does not widen as macOS expects", where, pname, cp));
                                break;
                            }
            } else if (thunks) {
                // A function pointer inside a structure is not converted.
                const std::string rt = resolved(d, p.type);
                for (const auto& [name, r] : d.records_by_name)
                    if (rt.find(name) != std::string::npos)
                        for (const auto& fld : r.fields)
                            if (is_function_pointer(d, fld.type))
                                problems.push_back(std::format("{} takes {}, whose field `{}' is a function pointer, which is not converted on x86-64 Windows", where, pname, fld.name));
            }
        }
        if (exported && !exported->contains(f.name))
            problems.push_back(std::format("{} is not exported by {}", where, image.filename().string()));
    }
    if (d.functions.empty() && problems.empty())
        problems.push_back(std::format("{} declares no function", lib.header));
    if (!problems.empty()) {
        std::string what = std::format("{}: the boundary of {} does not hold:", label, lib.header);
        for (const auto& p : problems) what += "\n  - " + p;
        refuse(what, "the interface between a program and an image is C, of fixed widths, with prototyped callbacks (openkal-image docs/bind.md)");
        return 1;
    }

    const fs::path source = out / std::format("{}_openkal_bind.c", mcpp::package_name());
    const std::string code = generate(d, header.filename().string(), image.filename().string(), label, sysv, thunks);
    if (read_text(source) != code) {
        std::ofstream o(source, std::ios::binary | std::ios::trunc);
        o << code;
    }
    mcpp::include_dir(header.parent_path().generic_string().c_str());
    mcpp::generated(source.generic_string().c_str());
    mcpp::deploy(image_rel.c_str(), ".");
    return 0;
}

}  // namespace mcpp::mcpplibs::openkal_bind
