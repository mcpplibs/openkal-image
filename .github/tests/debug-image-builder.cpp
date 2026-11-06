#include "debug_image.h"
#include "elf.h"
#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <map>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace e = okld::elf;
using Bytes = std::vector<unsigned char>;
void require(bool v, const char* why) { if (!v) throw std::runtime_error(why); }

struct Heap {
    std::map<void*, okld_size> live;
    std::map<void*, void*> original;
    unsigned allocations = 0, releases = 0, fail_at = 0;
    bool bad_release = false, skew = false;
    static void* allocate(okld_size n, void* ctx) {
        auto& h = *static_cast<Heap*>(ctx);
        if (++h.allocations == h.fail_at || n > 16 * 1024 * 1024) return nullptr;
        void* raw = std::malloc((n ? n : 1) + (h.skew ? 1 : 0));
        void* p = raw ? static_cast<unsigned char*>(raw)+(h.skew ? 1 : 0) : nullptr;
        if (p) { h.live.emplace(p, n); h.original.emplace(p, raw); }
        return p;
    }
    static void release(void* p, okld_size n, void* ctx) {
        auto& h = *static_cast<Heap*>(ctx);
        auto i = h.live.find(p);
        if (i == h.live.end()) { h.bad_release = true; return; }
        h.bad_release |= i->second != n;
        h.live.erase(i);
        ++h.releases;
        std::free(h.original.at(p)); h.original.erase(p);
    }
    okld_host host() {
        okld_host h{};
        h.alloc = allocate; h.free = release; h.ctx = this;
        return h;
    }
    ~Heap() { for (auto [p, raw] : original) std::free(raw); }
};

struct Fixture {
    Bytes b = Bytes(1048, 0);
    e::ehdr& header() { return *reinterpret_cast<e::ehdr*>(b.data()); }
    e::shdr& section(unsigned n) { return reinterpret_cast<e::shdr*>(b.data()+64)[n]; }
    e::sym& symbol(unsigned n = 1) { return reinterpret_cast<e::sym*>(b.data()+832)[n]; }
    e::rela& relocation() { return *reinterpret_cast<e::rela*>(b.data()+1024); }
    Fixture(bool packed = false, bool arm = false) {
        auto& h = header();
        h.ident[0]=0x7f; h.ident[1]='E'; h.ident[2]='L'; h.ident[3]='F';
        h.ident[4]=2; h.ident[5]=1; h.ident[6]=1;
        h.type=e::et_dyn; h.machine=arm ? e::em_aarch64 : e::em_x86_64;
        h.version=1; h.ehsize=64; h.shoff=64; h.shentsize=64; h.shnum=8; h.shstrndx=1;
        std::string names(1, '\0');
        auto name = [&](const char* s) { unsigned at=names.size(); names+=s; names+='\0'; return at; };
        section(1)={name(".shstrtab"),3,0,0,576,0,0,0,1,0};
        section(2)={name(".text"),1,2,0x1000,768,32,0,0,16,0};
        section(3)={name(".strtab"),3,0,0,800,5,0,0,1,0};
        section(4)={name(".symtab"),2,0,0,832,48,3,1,8,24};
        section(5)={name(".debug_info"),1,0,0,896,8,0,0,8,0};
        section(6)={name(".rela.debug_info"),4,0,0,1024,24,4,5,8,24};
        section(7)={name(".bss"),8,2,0x2000,0,16,0,0,8,0};
        section(1).size=names.size(); std::memcpy(b.data()+576,names.data(),names.size());
        std::memcpy(b.data()+800,"\0foo",5);
        symbol()={1,18,0,2,0x1004,4};
        relocation()={0,(e::u64{1}<<32)|(arm ? 257 : 1),0};
        if (packed) {
            // RFC 1950 zlib stream for the eight independent fixture bytes.
            const unsigned char packed[]={120,218,19,50,9,171,152,181,231,222,7,0,13,168,4,57};
            const unsigned long length=sizeof packed;
            std::memcpy(b.data()+920,packed,sizeof packed);
            struct Chdr { e::u32 type,reserved; e::u64 size,alignment; } c{1,0,8,8};
            std::memcpy(b.data()+896,&c,24); section(5).flags=0x800; section(5).size=24+length;
        }
    }
};

using Inspect = std::function<void(const unsigned char*,okld_size)>;
void exercise(Fixture f, bool expected, Inspect inspect = {}, unsigned fail_at = 0,
              e::u64 base = 0x40000000, okld_size extent = ~okld_size{0}, bool skew = false) {
    const Bytes before=f.b;
    Heap heap; heap.fail_at=fail_at; heap.skew=skew;
    auto host=heap.host();
    void* out=reinterpret_cast<void*>(0x1234); okld_size size=123;
    okld_why why{};
    const bool got=okld::debugger_image(f.b.data(),std::min(extent,f.b.size()),base,&host,&out,&size,&why);
    require(got==expected,got ? "unexpected acceptance" : why.text);
    require(f.b==before,"builder mutated source image");
    if (got) {
        require(out && size>=f.b.size(),"missing complete owned object");
        require(heap.live.size()==1 && heap.releases==0,"successful allocation ownership");
        if (inspect) inspect(static_cast<unsigned char*>(out),size);
        host.free(out,size,host.ctx);
    } else require(out==nullptr && size==0,"failure did not clear ownership outputs");
    require(heap.live.empty() && !heap.bad_release,"allocation leak or incorrect free size");
    if (skew) require(heap.allocations==1 && heap.releases==1,"misaligned allocation was not released");
}

using Case=std::pair<const char*,std::function<void()>>;
std::vector<Case> cases() {
    std::vector<Case> out;
    auto reject=[&](const char* name,std::function<void(Fixture&)> mutate,bool compressed=false) {
        out.emplace_back(name,[=]{Fixture f(compressed);mutate(f);exercise(f,false);});
    };
    out.emplace_back("placed_symbols_and_relocations",[]{exercise(Fixture{},true,[](const unsigned char* p,okld_size n){
        const auto& h=*reinterpret_cast<const e::ehdr*>(p);const auto* sh=reinterpret_cast<const e::shdr*>(p+64);
        const auto* sy=reinterpret_cast<const e::sym*>(p+832);const auto* re=reinterpret_cast<const e::rela*>(p+1024);
        require(h.type==1 && h.entry==0 && h.phoff==0 && h.phnum==0 && h.phentsize==0,"ET_REL header");
        require(sh[2].addr==0x40001000 && sh[7].addr==0x40002000,"allocated placement");
        require(sy[1].value==4 && sy[1].shndx==2 && re->offset==0 && n==1048,"relative symbol/relocation");
    });});
    out.emplace_back("compressed_source_copy",[]{exercise(Fixture(true),true,[](const unsigned char* p,okld_size n){
        const auto* sh=reinterpret_cast<const e::shdr*>(p+64);const unsigned char expected[]={0x12,0x34,0x56,0x78,0x9a,0xbc,0xde,0xf0};
        require(n==1056 && sh[5].offset==1048 && sh[5].size==8 && !(sh[5].flags&0x800),"inflated metadata");
        require(std::memcmp(p+sh[5].offset,expected,8)==0,"inflated bytes");
    });});
    out.emplace_back("aarch64_relocation",[]{exercise(Fixture(false,true),true);});
    out.emplace_back("all_1048_truncated_prefixes",[]{for(okld_size n=0;n<1048;++n)exercise(Fixture{},false,{},0,0x40000000,n);});
    reject("bad_magic",[](Fixture& f){f.header().ident[0]=0;});
    reject("wrong_class",[](Fixture& f){f.header().ident[4]=1;});
    reject("wrong_endian",[](Fixture& f){f.header().ident[5]=2;});
    reject("wrong_type",[](Fixture& f){f.header().type=2;});
    reject("unsupported_machine",[](Fixture& f){f.header().machine=3;});
    reject("wrong_section_entry_size",[](Fixture& f){f.header().shentsize=63;});
    reject("empty_section_table",[](Fixture& f){f.header().shnum=0;});
    reject("section_table_unaligned",[](Fixture& f){f.header().shoff=65;});
    reject("section_table_offset_wrap",[](Fixture& f){f.header().shoff=~e::u64{0}-7;});
    reject("string_index_outside_table",[](Fixture& f){f.header().shstrndx=8;});
    reject("names_wrong_type",[](Fixture& f){f.section(1).type=1;});
    reject("names_truncated",[](Fixture& f){f.section(1).size=~e::u64{0};});
    reject("name_offset_outside_table",[](Fixture& f){f.section(2).name=f.section(1).size;});
    reject("unterminated_name",[](Fixture& f){f.b[576+f.section(1).size-1]='X';});
    reject("section_range_overflow",[](Fixture& f){f.section(2).offset=~e::u64{0};f.section(2).size=1;});
    reject("section_size_overflow",[](Fixture& f){f.section(2).size=~e::u64{0};});
    reject("symbol_bad_entry_size",[](Fixture& f){f.section(4).entsize=23;});
    reject("symbol_partial_entry",[](Fixture& f){f.section(4).size=47;});
    reject("symbol_unaligned",[](Fixture& f){f.section(4).offset=833;});
    reject("symbol_bad_link",[](Fixture& f){f.section(4).link=8;});
    reject("symbol_link_not_strings",[](Fixture& f){f.section(4).link=2;});
    reject("symbol_bad_section",[](Fixture& f){f.symbol().shndx=8;});
    reject("native_tls_symbol",[](Fixture& f){f.symbol().info=22;});
    reject("relocation_bad_entry_size",[](Fixture& f){f.section(6).entsize=23;});
    reject("relocation_partial_entry",[](Fixture& f){f.section(6).size=23;});
    reject("relocation_unaligned",[](Fixture& f){f.section(6).offset=1023;});
    reject("relocation_bad_link",[](Fixture& f){f.section(6).link=8;});
    reject("relocation_link_not_symbols",[](Fixture& f){f.section(6).link=3;});
    reject("relocation_bad_target",[](Fixture& f){f.section(6).info=8;});
    reject("missing_debug_relocations",[](Fixture& f){f.section(6).size=0;});
    reject("relocation_missing_symbol",[](Fixture& f){f.relocation().info=(e::u64{2}<<32)|1;});
    reject("relocation_unknown_type",[](Fixture& f){f.relocation().info=(e::u64{1}<<32)|0xffff;});
    reject("relocation_eight_bytes_cross_end",[](Fixture& f){f.relocation().offset=1;});
    reject("relocation_before_target",[](Fixture& f){f.section(5).addr=1;});
    out.emplace_back("relocation_four_bytes_last_slot",[]{Fixture f;f.relocation().info=(e::u64{1}<<32)|10;f.relocation().offset=4;exercise(f,true);});
    reject("relocation_four_bytes_cross_end",[](Fixture& f){f.relocation().info=(e::u64{1}<<32)|10;f.relocation().offset=5;});
    out.emplace_back("linker_header_symbol_absolute",[]{Fixture f;f.symbol().value=0;exercise(f,true,[](const unsigned char* p,okld_size){const auto* s=reinterpret_cast<const e::sym*>(p+832);require(s[1].shndx==e::shn_abs && s[1].value==0x40000000,"linker header placement");});});
    reject("nonallocated_symbol_before_section",[](Fixture& f){f.symbol().shndx=5;f.symbol().value=0;f.section(5).addr=1;});
    out.emplace_back("allocated_address_overflow",[]{exercise(Fixture{},false,{},0,~e::u64{0}-0x1000);});
    reject("compressed_header_truncated",[](Fixture& f){f.section(5).size=23;},true);
    reject("unsupported_compression_type",[](Fixture& f){f.b[896]=2;},true);
    reject("compression_reserved_field",[](Fixture& f){f.b[900]=1;},true);
    reject("compression_bad_alignment",[](Fixture& f){e::u64 v=3;std::memcpy(f.b.data()+912,&v,8);},true);
    reject("compression_size_overflow",[](Fixture& f){e::u64 v=~e::u64{0};std::memcpy(f.b.data()+904,&v,8);},true);
    reject("compressed_allocated_section",[](Fixture& f){f.section(5).flags|=2;},true);
    reject("compressed_non_debug_section",[](Fixture& f){f.section(5).name=f.section(2).name;},true);
    reject("zlib_checksum_mismatch",[](Fixture& f){f.b[896+f.section(5).size-1]^=1;},true);
    reject("zlib_header_invalid",[](Fixture& f){f.b[920]=0;},true);
    reject("zlib_stream_invalid",[](Fixture& f){f.b[922]^=0xff;},true);
    reject("zlib_inflated_size_mismatch",[](Fixture& f){e::u64 v=9;std::memcpy(f.b.data()+904,&v,8);},true);
    out.emplace_back("allocation_failure_no_ownership",[]{exercise(Fixture(true),false,{},1);});
    out.emplace_back("misaligned_host_allocation_rejected_and_released",[]{exercise(Fixture{},false,{},0,0x40000000,~okld_size{0},true);});
    out.emplace_back("unaligned_source_explicitly_rejected",[]{
        Fixture f;Bytes bytes(f.b.size()+1);std::copy(f.b.begin(),f.b.end(),bytes.begin()+1);
        Heap heap;auto host=heap.host();void* p=reinterpret_cast<void*>(0x1234);okld_size n=123;okld_why why{};
        require(!okld::debugger_image(bytes.data()+1,f.b.size(),0x40000000,&host,&p,&n,&why),"unaligned source accepted");
        require(!p && !n && !heap.allocations && heap.live.empty(),"unaligned source acquired ownership");
    });
    out.emplace_back("missing_input_or_allocator_callbacks",[]{
        for(unsigned mode=0;mode<4;++mode){
            Fixture f;Heap heap;auto host=heap.host();
            if(mode==1)host.alloc=nullptr;if(mode==2)host.free=nullptr;
            void* output=reinterpret_cast<void*>(0x1234);okld_size size=123;okld_why why{};
            const bool ok=okld::debugger_image(mode==3 ? nullptr : f.b.data(),f.b.size(),0x40000000,mode==0 ? nullptr : &host,&output,&size,&why);
            require(!ok && !output && !size && !heap.allocations,"invalid callbacks acquired ownership");
        }
    });
    out.emplace_back("compressed_alignment_padding",[]{Fixture f(true);e::u64 alignment=64;std::memcpy(f.b.data()+912,&alignment,8);exercise(f,true,[](const unsigned char* p,okld_size n){const auto* s=reinterpret_cast<const e::shdr*>(p+64);require(n==1096 && s[5].offset==1088 && s[5].addralign==64,"inflated alignment");for(unsigned i=1048;i<1088;++i)require(p[i]==0,"padding not initialized");});});
    out.emplace_back("allocated_target_relocation_uses_original_address",[]{
        Fixture f;f.b.resize(1072);f.section(7)={f.section(6).name,4,0,0,1048,24,4,2,8,24};
        e::rela r{0x1008,(e::u64{1}<<32)|1,0};std::memcpy(f.b.data()+1048,&r,24);
        exercise(f,true,[](const unsigned char* p,okld_size){require(reinterpret_cast<const e::rela*>(p+1048)->offset==8,"relocation subtracted placed rather than original target");});
    });
    out.emplace_back("runtime_relocation_is_retained_as_data",[]{
        Fixture f;f.b.resize(1072);f.section(7)={f.section(6).name,4,0,0,1048,24,4,0,8,24};
        e::rela r{0x1008,8,0x2000};std::memcpy(f.b.data()+1048,&r,24);
        exercise(f,true,[r](const unsigned char* p,okld_size){const auto* sh=reinterpret_cast<const e::shdr*>(p+64);require(sh[7].type==1 && !sh[7].link && !sh[7].info && !sh[7].entsize,"runtime relocation remained active");require(std::memcmp(p+1048,&r,24)==0,"runtime relocation bytes changed");});
    });
    out.emplace_back("all_relocation_width_boundaries",[]{
        const unsigned types[]={14,12,10,1,36,259,258,257,1031};
        const unsigned widths[]={1,2,4,8,16,2,4,8,16};
        for(unsigned n=0;n<9;++n){
            Fixture f(false,n>=5);f.section(5).size=16;f.relocation().info=(e::u64{1}<<32)|types[n];f.relocation().offset=16-widths[n];exercise(f,true);
            ++f.relocation().offset;exercise(f,false);
        }
    });
    out.emplace_back("none_relocation_has_no_target_write",[]{Fixture f;f.relocation().offset=~e::u64{0};f.relocation().info=0xffffffff00000000ull;exercise(f,true);});
    out.emplace_back("repeated_build_release",[]{for(int i=0;i<100;++i)exercise(Fixture(true),true);});
    return out;
}

int main(int argc,char** argv) {
    unsigned passed=0,failed=0;
    for(auto& [name,run] : cases()) {
        if(argc==2 && std::string(argv[1])!=name)continue;
        try {run();++passed;std::printf("PASS %s\n",name);}
        catch(const std::exception& error){++failed;std::printf("FAIL %s: %s\n",name,error.what());}
    }
    std::printf("RESULT %u passed %u failed\n",passed,failed);
    return failed || !passed;
}
