#include <okld.h>
#include <sys/mman.h>
#include <algorithm>
#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iterator>
#include <map>
#include <stdexcept>
#include <string>
#include <vector>

extern "C" {
struct jit_code_entry { jit_code_entry *next,*prev; const char* symfile_addr; unsigned long long symfile_size; };
struct jit_descriptor { unsigned version,action_flag; jit_code_entry *relevant_entry,*first_entry; };
extern jit_descriptor __jit_debug_descriptor;
}
void require(bool value,const char* message) { if(!value)throw std::runtime_error(message); }
using Bytes=std::vector<unsigned char>;
Bytes read(const char* name) { std::ifstream in(std::string("fixtures/")+name,std::ios::binary);require(bool(in),"fixture missing");return Bytes(std::istreambuf_iterator<char>(in),{}); }
unsigned modules() {
    unsigned n=0;okld_iterate([](void*,const void*,okld_u32,const char*,void* p){++*static_cast<unsigned*>(p);return 0;},&n);return n;
}
unsigned registrations() {
    unsigned n=0;for(auto* p=__jit_debug_descriptor.first_entry;p;p=p->next){require(++n<16,"bad JIT list");require(p->symfile_addr && p->symfile_size,"incomplete JIT entry");}return n;
}

struct Host {
    struct Region { okld_size size;std::string owner; };
    Bytes a=read("dep-a.oke"),b=read("dep-b.oke"),good=read("main-good.oke"),bad=read("main-no-relocs.oke");
    std::map<void*,okld_size> heap;
    std::map<void*,Region> regions;
    std::vector<std::string> source_stack,released;
    std::string root="main";
    unsigned finds=0,byte_releases=0,entry_allocations=0,fail_entry=0;
    bool fail_main_copy=false,bad_callback=false,shared=false;
    okld_host api{};
    Host(bool debug=true,bool transitive=false) : shared(transitive) {
        if(shared)a=read("dep-a-shared.oke");
        api.alloc=[](okld_size n,void* c)->void* {
            auto& s=*static_cast<Host*>(c);
            if(n==sizeof(jit_code_entry) && ++s.entry_allocations==s.fail_entry)return nullptr;
            if(s.fail_main_copy && n==s.good.size())return nullptr;
            void* p=std::malloc(n);if(p)s.heap.emplace(p,n);return p;
        };
        api.free=[](void* p,okld_size n,void* c){
            auto& s=*static_cast<Host*>(c);auto i=s.heap.find(p);
            if(i==s.heap.end()){s.bad_callback=true;return;}
            s.bad_callback|=i->second!=n;s.heap.erase(i);std::free(p);
        };
        api.reserve=[](okld_size n,void* c)->void* {
            auto& s=*static_cast<Host*>(c);const okld_size align=65536;
            void* raw=mmap(nullptr,n+align,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
            if(raw==MAP_FAILED)return nullptr;
            auto address=reinterpret_cast<std::uintptr_t>(raw);auto placed=(address+align-1)&~(align-1);
            if(placed>address)munmap(raw,placed-address);
            const auto trailing=n+align-(placed-address)-n;
            if(trailing)munmap(reinterpret_cast<void*>(placed+n),trailing);
            void* p=reinterpret_cast<void*>(placed);s.regions.emplace(p,Region{n,s.source_stack.empty()?s.root:s.source_stack.back()});return p;
        };
        api.publish=[](void* p,okld_size offset,okld_size n,void*){return mprotect(static_cast<unsigned char*>(p)+offset,n,PROT_READ|PROT_EXEC);};
        api.release=[](void* p,okld_size n,void* c){
            auto& s=*static_cast<Host*>(c);auto i=s.regions.find(p);
            if(i==s.regions.end()){s.bad_callback=true;return;}
            s.bad_callback|=i->second.size!=n;s.released.push_back(i->second.owner);
            s.regions.erase(i);s.bad_callback|=munmap(p,n)!=0;
        };
        api.granularity=[](void*)->okld_size{return 65536;};
        api.find_needed=[](const char* name,okld_size* n,void* c)->const void* {
            auto& s=*static_cast<Host*>(c);++s.finds;const Bytes* bytes=nullptr;
            if(std::strcmp(name,"dep-a.oke")==0)bytes=&s.a;
            if(std::strcmp(name,"dep-b.oke")==0)bytes=&s.b;
            if(!bytes)return nullptr;
            s.source_stack.emplace_back(name);*n=bytes->size();return bytes->data();
        };
        api.release_bytes=[](const void* p,okld_size n,void* c){
            auto& s=*static_cast<Host*>(c);++s.byte_releases;
            s.bad_callback|=!((p==s.a.data() && n==s.a.size())||(p==s.b.data() && n==s.b.size()));
            if(s.source_stack.empty())s.bad_callback=true;else s.source_stack.pop_back();
        };
        api.debugger=debug;api.ctx=this;
    }
    ~Host() {for(auto [p,n]:heap)std::free(p);for(auto [p,r]:regions)munmap(p,r.size);}
    void clean() {
        require(!bad_callback && source_stack.empty(),"callback identity mismatch");
        if(!heap.empty() || !regions.empty() || modules() || registrations()) {
            std::printf("RESOURCE heap=%zu regions=%zu modules=%u registrations=%u\n",heap.size(),regions.size(),modules(),registrations());
            throw std::runtime_error("loader reference or allocation leaked");
        }
    }
    okld_module* preload() {
        root="preloaded-a";okld_module* m=nullptr;okld_why why{};
        require(okld_load(a.data(),a.size(),"dep-a.oke",&api,&m,&why)==0,why.text);
        require(m && reinterpret_cast<int(*)()>(okld_entry(m))()==17,"dependency does not execute");
        root="main";return m;
    }
    void fail(bool previous=false,int failure=0) {
        okld_module* existing=previous?preload():nullptr;
        const auto before_heap=heap.size(),before_regions=regions.size();
        const auto before_reg=registrations(),before_modules=modules(),before_finds=finds,before_byte_releases=byte_releases;
        if(failure==1)fail_main_copy=true;
        if(failure==2)fail_entry=3;
        const auto& image=failure?good:bad;const Bytes original=image;
        okld_module* result=nullptr;okld_why why{};
        const int rc=okld_load(image.data(),image.size(),"main.oke",&api,&result,&why);
        require(rc!=0 && result==nullptr,"announcement failure did not refuse the image");
        require(std::strstr(why.text,failure==2?"debugger registration":failure==1?"debugger object":"retained link relocations"),"failure did not reach announcement");
        const unsigned lookups=shared && !previous ? 3 : 2;
        require(image==original && finds-before_finds==lookups && byte_releases-before_byte_releases==lookups,"input or source-release identity changed");
        if(heap.size()!=before_heap || regions.size()!=before_regions || modules()!=before_modules || registrations()!=before_reg)
            std::printf("ROLLBACK before_heap=%zu after_heap=%zu before_regions=%zu after_regions=%zu modules=%u registrations=%u\n",before_heap,heap.size(),before_regions,regions.size(),modules(),registrations());
        require(heap.size()==before_heap && regions.size()==before_regions && modules()==before_modules && registrations()==before_reg,"announcement retained dependencies");
        const std::vector<std::string> order=previous ? (shared ? std::vector<std::string>{"main"} : std::vector<std::string>{"dep-b.oke","main"}) : std::vector<std::string>{"dep-b.oke","dep-a.oke","main"};
        require(released==order,"announcement rollback order changed");
        if(existing) {
            require(reinterpret_cast<int(*)()>(okld_entry(existing))()==17,"rollback broke an existing owner");
            okld_unload(existing);
        }
        clean();
    }
    void success(bool debugger) {
        require(bool(api.debugger)==debugger,"control setup mismatch");
        const auto& image=debugger?good:bad;okld_module* result=nullptr;okld_why why{};
        require(okld_load(image.data(),image.size(),"main.oke",&api,&result,&why)==0,why.text);
        require(modules()==3 && registrations()==(debugger?3u:0u),"successful module/JIT registration count");
        require(reinterpret_cast<int(*)()>(okld_entry(result))()==42,"linked dependency program does not execute");
        okld_unload(result);clean();
    }
};

int main(int argc,char** argv) {
    const std::string which=argc==2?argv[1]:"all";
    const std::vector<std::string> names={"ordinary-no-relocs","debugger-good","failed-main-fresh","failed-main-preloaded","failed-shared-subdependency","failed-preloaded-transitive-owner","copy-allocation-failure","entry-allocation-failure","repeated-failure"};
    unsigned passed=0,failed=0;
    for(const auto& name:names) {
        if(which!="all" && which!=name)continue;
        try {
            require(modules()==0 && registrations()==0,"previous case left state");
            if(name=="ordinary-no-relocs"){Host host(false);host.success(false);}
            if(name=="debugger-good"){Host host;host.success(true);}
            if(name=="failed-main-fresh"){Host host;host.fail();}
            if(name=="failed-main-preloaded"){Host host;host.fail(true);}
            if(name=="failed-shared-subdependency"){Host host(true,true);host.fail();}
            if(name=="failed-preloaded-transitive-owner"){Host host(true,true);host.fail(true);}
            if(name=="copy-allocation-failure"){Host host;host.fail(false,1);}
            if(name=="entry-allocation-failure"){Host host;host.fail(false,2);}
            if(name=="repeated-failure")for(unsigned n=0;n<20;++n){Host host;host.fail();}
            ++passed;std::printf("PASS %s\n",name.c_str());
        } catch(const std::exception& e){++failed;std::printf("FAIL %s: %s\n",name.c_str(),e.what());break;}
    }
    std::printf("RESULT %u passed %u failed\n",passed,failed);return failed || !passed;
}
