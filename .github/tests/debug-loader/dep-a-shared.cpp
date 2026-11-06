extern "C" int dep_b();
extern "C" int dep_a() { return dep_b() - 8; }
