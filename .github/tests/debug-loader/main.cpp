extern "C" int dep_a();
extern "C" int dep_b();
extern "C" int program() { return dep_a() + dep_b(); }
