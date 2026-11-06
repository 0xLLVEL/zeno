//=================
// Credoxy 2.6.9
// version-f0ea5da9412f4e35
// dumped 13/13
// dump time: 49.507s
//=================

#define CLOSURE_CONT_ENC vmval4
#define LSTATE_STACKSIZE_ENC vmval1
#define PROTO_ABSLINEINFO_ENC vmval4
#define PROTO_DEBUGINSN_ENC vmval4
#define PROTO_DEBUGNAME_ENC vmval4
#define PROTO_LINEINFO_ENC vmval3
#define PROTO_LOCVARS_ENC vmval2
#define PROTO_SOURCE_ENC vmval1
#define PROTO_TYPEINFO_ENC vmval4
#define PROTO_UPVALUES_ENC vmval2
#define PROTO_USERDATA_ENC vmval3
#define TSTRING_HASH_ENC vmval2
#define UDATA_META_ENC vmval2

struct Proto; struct lua_State; struct global_State;
struct CallInfo; struct LuaTable; struct LuaNode;
struct TString; struct LocVar; struct TValue;
struct Instruction; struct GCObject; struct UpVal;
struct Udata; struct Closure; struct RobloxExtraSpace;
struct Shared; struct SharedExtraSpace; struct Identity;
struct FeedbackVectorSlot; struct GCStats; struct GCMetrics;
struct lua_Callbacks; struct lua_Debug; struct lua_Page;
struct stringtable; struct lua_ExecutionCallbacks;
struct lua_UdataDirectAccessData; struct lua_UserdataMark;
struct lua_EmbedderGc; struct RegistryFree;

typedef TValue* StkId;
typedef void* (*lua_Alloc)(void* ud, void* ptr, size_t osize, size_t nsize);
typedef int (*lua_CFunction)(lua_State* L);
typedef int (*lua_Continuation)(lua_State* L, int status);

// array bounds, from the span each table occupies
#define LUA_MEMORY_CATEGORIES      256

// gcobject: 3/3 members
struct GCObject {
    uint8_t                                   marked;                       // 0x0
    uint8_t                                   tt;                           // 0x1
    uint8_t                                   memcat;                       // 0x2
};

// proto: 43/43 members; 2 unnamed observed storage range(s)
struct Proto {
    uint8_t                                   marked;                       // 0x0
    uint8_t                                   tt;                           // 0x1
    uint8_t                                   memcat;                       // 0x2
    uint8_t                                   is_vararg;                    // 0x3
    uint8_t                                   maxstacksize;                 // 0x4
    uint8_t                                   nups;                         // 0x5
    uint8_t                                   flags;                        // 0x6
    uint8_t                                   numparams;                    // 0x7
    void*                                     execdata;                     // 0x8
    uintptr_t                                 exectarget;                   // 0x10
    uint8_t                                   execflags;                    // 0x18
    uint8_t                                   field_0x19[7];                // 0x19  // observed storage
    PROTO_DEBUGNAME_ENC<TString*>             debugname;                    // 0x20  VMValue4
    uint32_t                                  execcount;                    // 0x28
    uint32_t                                  field_0x2c;                   // 0x2c  // observed storage
    PROTO_TYPEINFO_ENC<uint8_t*>              typeinfo;                     // 0x30  VMValue4
    GCObject*                                 gclist;                       // 0x38
    PROTO_LINEINFO_ENC<uint8_t*>              lineinfo;                     // 0x40  VMValue3
    PROTO_DEBUGINSN_ENC<uint8_t*>             debuginsn;                    // 0x48  VMValue4
    struct Proto**                            p;                            // 0x50
    PROTO_SOURCE_ENC<TString*>                source;                       // 0x58  VMValue1
    TValue*                                   k;                            // 0x60
    Instruction*                              code;                         // 0x68
    PROTO_ABSLINEINFO_ENC<int*>               abslineinfo;                  // 0x70  VMValue4
    PROTO_LOCVARS_ENC<struct LocVar*>         locvars;                      // 0x78  VMValue2
    PROTO_USERDATA_ENC<void*>                 userdata;                     // 0x80  VMValue3
    PROTO_UPVALUES_ENC<TString**>             upvalues;                     // 0x88  VMValue2
    const Instruction*                        codeentry;                    // 0x90
    int                                       sizeupvalues;                 // 0x98
    int                                       sizelocvars;                  // 0x9c
    int                                       sizep;                        // 0xa0
    int                                       linedefined;                  // 0xa4
    int                                       sizecode;                     // 0xa8
    int                                       sizek;                        // 0xac
    int                                       sizelineinfo;                 // 0xb0
    int                                       bytecodeid;                   // 0xb4
    int                                       sizetypeinfo;                 // 0xb8
    int                                       linegaplog2;                  // 0xbc
    FeedbackVectorSlot*                       feedbackvec;                  // 0xc0
    uint32_t                                  feedbackvecsize;              // 0xc8
    uint32_t                                  funid;                        // 0xcc
    Proto*                                    optimized;                    // 0xd0
    Proto*                                    deoptimized;                  // 0xd8
    uint64_t                                  cost;                         // 0xe0
    void*                                     newmember;                    // 0xe8
};

// tstring: 9/9 members; 6 unnamed observed storage range(s)
struct TString {
    uint8_t                                   marked;                       // 0x0
    uint8_t                                   tt;                           // 0x1
    uint8_t                                   memcat;                       // 0x2
    char  _gap_0x3[0x1];
    uint16_t                                  atomflag;                     // 0x4
    int16_t                                   atom;                         // 0x6
    TString*                                  next;                         // 0x8
    TSTRING_HASH_ENC<unsigned int>            hash;                         // 0x10  VMValue2
    unsigned int                              len;                          // 0x14
    char                                      data[1];                      // 0x18
    uint8_t                                   field_0x19;                   // 0x19  // observed storage
    uint8_t                                   field_0x1a;                   // 0x1a  // observed storage; zero initialization observed
    char  _gap_0x1b[0x1];
    uint8_t                                   field_0x1c;                   // 0x1c  // observed storage
    uint8_t                                   field_0x1d;                   // 0x1d  // observed storage; zero initialization observed
    uint8_t                                   field_0x1e;                   // 0x1e  // observed storage; zero initialization observed
    uint8_t                                   field_0x1f;                   // 0x1f  // observed storage; zero initialization observed
};

// udata: 7/7 members; 1 unnamed observed storage range(s)
struct Udata {
    uint8_t                                   marked;                       // 0x0
    uint8_t                                   tt;                           // 0x1
    uint8_t                                   memcat;                       // 0x2
    uint8_t                                   tag;                          // 0x3
    int                                       len;                          // 0x4
    UDATA_META_ENC<struct LuaTable*>          metatable;                    // 0x8  VMValue2
    char                                      data[1];                      // 0x10
    uint8_t                                   field_0x11[7];                // 0x11  // observed storage
};

// stringtable: 3/3 members; 2 unnamed observed storage range(s)
struct stringtable {
    uint32_t                                  field_0x0;                    // 0x0  // observed storage
    uint32_t                                  nuse;                         // 0x4
    int                                       size;                         // 0x8
    uint8_t                                   field_0xc;                    // 0xc  // observed storage
    char  _gap_0xd[0x3];
    TString**                                 hash;                         // 0x10
};

// TValue: 3/3 members
struct TValue {
    Value                                     value;                        // 0x0
    int                                       extra;                        // 0x8
    int                                       tt;                           // 0xc
};

// Closure: 14/15 members
struct Closure {
    uint8_t                                   marked;                       // 0x0
    uint8_t                                   tt;                           // 0x1
    uint8_t                                   memcat;                       // 0x2
    uint8_t                                   preload;                      // 0x3
    uint8_t                                   nupvalues;                    // 0x4
    uint8_t                                   isC;                          // 0x5
    uint8_t                                   stacksize;                    // 0x6
    char  _gap_0x7[0x1];
    GCObject*                                 gclist;                       // 0x8
    struct LuaTable*                          env;                          // 0x10
    TString*                                  u_debugname;                  // 0x18  // union member c.debugname
    CLOSURE_CONT_ENC<lua_Continuation>        u_cont;                       // 0x20  VMValue4  // union member c.cont
    lua_CFunction                             u_f;                          // 0x28  // union member c.f
    TValue                                    u_upvals[1];                  // 0x30  // union member c.upvals
};

// LuaTable: 14/14 members
struct LuaTable {
    uint8_t                                   marked;                       // 0x0
    uint8_t                                   tt;                           // 0x1
    uint8_t                                   memcat;                       // 0x2
    uint8_t                                   tmcache;                      // 0x3
    uint8_t                                   safeenv;                      // 0x4
    uint8_t                                   nodemask8;                    // 0x5
    uint8_t                                   readonly;                     // 0x6
    uint8_t                                   lsizenode;                    // 0x7
    int                                       sizearray;                    // 0x8
    int                                       lastfree;                     // 0xc
    struct LuaTable*                          metatable;                    // 0x10
    GCObject*                                 gclist;                       // 0x18
    LuaNode*                                  node;                         // 0x20
    TValue*                                   array;                        // 0x28
};

// LuaNode: 2/2 members
struct LuaNode {
    TValue                                    val;                          // 0x0
    TKey                                      key;                          // 0x10
};

// CallInfo: 7/7 members
struct CallInfo {
    StkId                                     base;                         // 0x0
    StkId                                     top;                          // 0x8
    StkId                                     func;                         // 0x10
    Proto*                                    p;                            // 0x18
    const Instruction*                        savedpc;                      // 0x20
    int                                       nresults;                     // 0x28
    unsigned int                              flags;                        // 0x2c
};

// lua_State: 26/26 members; 1 unnamed observed storage range(s)
struct lua_State {
    uint8_t                                   marked;                       // 0x0
    uint8_t                                   tt;                           // 0x1
    uint8_t                                   memcat;                       // 0x2
    uint8_t                                   status;                       // 0x3  VMValue3
    bool                                      singlestep;                   // 0x4
    bool                                      isactive;                     // 0x5
    uint8_t                                   activememcat;                 // 0x6
    uint8_t                                   field_0x7;                    // 0x7  // observed storage
    RobloxExtraSpace*                         userdata;                     // 0x8
    LuaTable*                                 gt;                           // 0x10
    TString*                                  namecall;                     // 0x18
    CallInfo*                                 end_ci;                       // 0x20
    CallInfo*                                 base_ci;                      // 0x28
    UpVal*                                    openupval;                    // 0x30
    unsigned short                            nCcalls;                      // 0x38
    unsigned short                            baseCcalls;                   // 0x3a
    int                                       cachedslot;                   // 0x3c
    GCObject*                                 gclist;                       // 0x40
    StkId                                     stack;                        // 0x48
    global_State*                             global;                       // 0x50
    StkId                                     base;                         // 0x58  VMValue3
    StkId                                     top;                          // 0x60
    StkId                                     stack_last;                   // 0x68
    CallInfo*                                 ci;                           // 0x70
    LSTATE_STACKSIZE_ENC<int>                 stacksize;                    // 0x78  VMValue1
    int                                       size_ci;                      // 0x7c
    LuaTable*                                 finalizers;                   // 0x80
};

// lua_Callbacks: 11/13 members; 2 unnamed observed storage range(s)
struct lua_Callbacks {
    void*                                     userdata;                     // 0x0
                                              void(*onallocate)(lua_State*,void*,size_t,size_t,uint8_t,int,int);  // 0x8
    uint64_t                                  field_0x10;                   // 0x10  // observed storage
                                              void(*debugprotectederror)(lua_State*);  // 0x18
                                              void(*userthread)(lua_State*,lua_State*);  // 0x20
                                              int16_t(*useratom)(lua_State*,const char*,size_t);  // 0x28
                                              void(*preresume)(lua_State*); // 0x30
                                              void(*debugstep)(lua_State*,lua_Debug*);  // 0x38
                                              void(*postresume)(lua_State*);  // 0x40
                                              void(*onfree)(lua_State*,void*);  // 0x48
    uint8_t                                   field_0x50[16];               // 0x50  // observed storage
                                              void(*interrupt)(lua_State*,int);  // 0x60
                                              void(*debugbreak)(lua_State*,lua_Debug*);  // 0x68
};

// lua_Page: 11/11 members
struct lua_Page {
    lua_Page*                                 listprev;                     // 0x0
    lua_Page*                                 listnext;                     // 0x8
    lua_Page*                                 prev;                         // 0x10
    lua_Page*                                 next;                         // 0x18
    int                                       pageSize;                     // 0x20
    int                                       blockSize;                    // 0x24
    void*                                     freeList;                     // 0x28
    int                                       freeNext;                     // 0x30
    char  _gap_0x34[0x4];
    int                                       busyBlocks;                   // 0x38
    char                                      padding[8];                   // 0x3c
};

// lua_debug: 13/13 members
struct lua_Debug {
    const char*                               short_src;                    // 0x0
    const char*                               source;                       // 0x8
    const char*                               what;                         // 0x10
    const char*                               name;                         // 0x18
    int                                       linedefined;                  // 0x20
    int                                       protoid;                      // 0x24
    int                                       currentline;                  // 0x28
    int                                       bytecodeid;                   // 0x2c
    void*                                     userdata;                     // 0x30
    uint8_t                                   nupvals;                      // 0x38
    uint8_t                                   isvararg;                     // 0x39
    uint8_t                                   nparams;                      // 0x3a
    char                                      ssbuf;                        // 0x3b
};

// lua_ExecutionCallbacks: 5 recovered slots
struct lua_ExecutionCallbacks {
    uint8_t                                   field_0x0[16];                // 0x0  // observed storage
                                              void(*destroy)(lua_State*, Proto*);  // 0x10
    uint64_t                                  field_0x18;                   // 0x18  // observed storage
    uint8_t                                   field_0x20[16];               // 0x20  // observed storage
    uint64_t                                  field_0x30;                   // 0x30  // observed storage
};

// UpVal: 8 recovered slots
struct UpVal {
    uint8_t                                   field_0x0;                    // 0x0  // observed storage
    uint8_t                                   field_0x1;                    // 0x1  // observed storage
    uint8_t                                   field_0x2;                    // 0x2  // observed storage
    uint8_t                                   field_0x3;                    // 0x3  // observed storage; zero initialization observed
    char  _gap_0x4[0x4];
    TValue*                                   v;                            // 0x8
    uint64_t                                  field_0x10;                   // 0x10  // observed storage
    uint64_t                                  field_0x18;                   // 0x18  // observed storage
    uint64_t                                  field_0x20;                   // 0x20  // observed storage
};

// GCStats: 16 recovered slots
struct GCStats {
    uint8_t                                   field_0x0[16];                // 0x0  // observed storage
    uint8_t                                   field_0x10[16];               // 0x10  // observed storage
    uint8_t                                   field_0x20[16];               // 0x20  // observed storage
    uint8_t                                   field_0x30[16];               // 0x30  // observed storage
    uint8_t                                   field_0x40[16];               // 0x40  // observed storage
    uint8_t                                   field_0x50[16];               // 0x50  // observed storage
    uint8_t                                   field_0x60[16];               // 0x60  // observed storage
    uint8_t                                   field_0x70[16];               // 0x70  // observed storage
    uint32_t                                  field_0x80;                   // 0x80  // observed storage
    uint32_t                                  field_0x84;                   // 0x84  // observed storage
    uint64_t                                  field_0x88;                   // 0x88  // observed storage
    uint64_t                                  field_0x90;                   // 0x90  // observed storage
    uint64_t                                  field_0x98;                   // 0x98  // observed storage
    uint64_t                                  field_0xa0;                   // 0xa0  // observed storage
    uint64_t                                  field_0xa8;                   // 0xa8  // observed storage
    uint64_t                                  field_0xb0;                   // 0xb0  // observed storage
};

// lua_UdataDirectAccessData: 6 recovered slots
struct lua_UdataDirectAccessData {
    uint64_t                                  field_0x0;                    // 0x0  // observed storage
    char  _gap_0x8[0x4];
    uint32_t                                  field_0xc;                    // 0xc  // observed storage
    uint64_t                                  field_0x10;                   // 0x10  // observed storage
    char  _gap_0x18[0x4];
    uint32_t                                  field_0x1c;                   // 0x1c  // observed storage
    uint64_t                                  field_0x20;                   // 0x20  // observed storage
    char  _gap_0x28[0x4];
    uint32_t                                  field_0x2c;                   // 0x2c  // observed storage
};

// global_state: 44/50 members; 56 unnamed observed storage range(s)
struct global_State {
    uint8_t                                   currentwhite;                 // 0x0
    uint8_t                                   field_0x1;                    // 0x1  // observed storage; zero initialization observed
    uint8_t                                   gcstate;                      // 0x2
    char  _gap_0x3[0x5];
    lua_Alloc                                 frealloc;                     // 0x8
    void*                                     ud;                           // 0x10
    int                                       gcstepsize;                   // 0x18
    int                                       gcstepmul;                    // 0x1c
    int                                       gcgoal;                       // 0x20
    uint8_t                                   field_0x24;                   // 0x24  // observed storage
    char  _gap_0x25[0x3];
    GCObject*                                 gray;                         // 0x28
    GCObject*                                 grayagain;                    // 0x30
    GCObject*                                 weak;                         // 0x38
    stringtable                               strt;                         // 0x40
    uint32_t                                  field_0x58;                   // 0x58  // observed storage
    uint8_t                                   field_0x5c;                   // 0x5c  // observed storage
    char  _gap_0x5d[0x3];
    size_t                                    GCthreshold;                  // 0x60
    size_t                                    totalbytes;                   // 0x68
    struct lua_Page*                          sweepgcopage;                 // 0x70
    struct lua_State*                         mainthread;                   // 0x78
    UpVal                                     uvhead;                       // 0x80
    struct lua_Page*                          allgcopages;                  // 0xa8
    struct lua_Page*                          freepages;                    // 0xb0
    char  _gap_0xb8[0x138];
    struct lua_Page*                          freegcopages;                 // 0x1f0
    char  _gap_0x1f8[0x140];
    struct LuaTable*                          mt;                           // 0x338
    char  _gap_0x340[0x20];
    uint64_t                                  field_0x360;                  // 0x360  // observed storage
    char  _gap_0x368[0x40];
    TString*                                  ttname;                       // 0x3a8
    char  _gap_0x3b0[0x40];
    uint64_t                                  field_0x3f0;                  // 0x3f0  // observed storage
    char  _gap_0x3f8[0x20];
    TString*                                  tmname;                       // 0x418
    uint64_t                                  field_0x420;                  // 0x420  // observed storage
    char  _gap_0x428[0x8];
    uint64_t                                  field_0x430;                  // 0x430  // observed storage
    uint64_t                                  field_0x438;                  // 0x438  // observed storage
    uint64_t                                  field_0x440;                  // 0x440  // observed storage
    uint64_t                                  field_0x448;                  // 0x448  // observed storage
    uint64_t                                  field_0x450;                  // 0x450  // observed storage
    uint64_t                                  field_0x458;                  // 0x458  // observed storage
    uint64_t                                  field_0x460;                  // 0x460  // observed storage
    uint64_t                                  field_0x468;                  // 0x468  // observed storage
    uint64_t                                  field_0x470;                  // 0x470  // observed storage
    uint64_t                                  field_0x478;                  // 0x478  // observed storage
    char  _gap_0x480[0x10];
    uint64_t                                  field_0x490;                  // 0x490  // observed storage
    uint64_t                                  field_0x498;                  // 0x498  // observed storage
    uint64_t                                  field_0x4a0;                  // 0x4a0  // observed storage
    char  _gap_0x4a8[0x8];
    uint64_t                                  field_0x4b0;                  // 0x4b0  // observed storage
    char  _gap_0x4b8[0x150];
    uint64_t                                  field_0x608;                  // 0x608  // observed storage
    char  _gap_0x610[0x10];
    TValue                                    pseudotemp;                   // 0x620
    TValue                                    registry;                     // 0x630
    RegistryFree                              registryfree;                 // 0x640
    char  _gap_0x644[0xc];
    uint64_t                                  ptrenckey[4];                 // 0x650
    lua_Callbacks                             cb;                           // 0x670
    uint64_t                                  rngstate;                     // 0x6e0
    lua_ExecutionCallbacks                    ecb;                          // 0x6e8
    uint64_t                                  field_0x730;                  // 0x730  // observed storage
    uint64_t                                  field_0x738;                  // 0x738  // observed storage
    char  _gap_0x740[0x200];
    lua_UdataDirectAccessData                 udatadirect;                  // 0x940
    char  _gap_0x988[0x2588];
    uint64_t                                  field_0x2f10;                 // 0x2f10  // observed storage
    char  _gap_0x2f18[0x940];
    size_t                                    memcatbytes[256];             // 0x3858
                                              void(*udatagc)(lua_State*,void*);  // 0x4058
    char  _gap_0x4060[0x3f8];
    lua_UserdataMark                          udatamark;                    // 0x4458
    char  _gap_0x4460[0x3f8];
    LuaTable*                                 udatamt;                      // 0x4858
    char  _gap_0x4860[0x3f8];
    TValue                                    weakregistry;                 // 0x4c58
    int                                       weakregistryfree;             // 0x4c68
    char  _gap_0x4c6c[0x4];
    lua_EmbedderGc                            embeddergc;                   // 0x4c70
    TString*                                  lightuserdataname;            // 0x4c78
    char  _gap_0x4c80[0x3f8];
    uint64_t                                  field_0x5078;                 // 0x5078  // observed storage
    char  _gap_0x5080[0x408];
    struct Closure*                           builtinPcall;                 // 0x5488
    struct Closure*                           builtinXpcall;                // 0x5490
    char  _gap_0x5498[0x48];
    GCStats                                   gcstats;                      // 0x54e0
    uint32_t                                  lastprotoid;                  // 0x5598
    uint32_t                                  lastclassid;                  // 0x559c
    GCMetrics                                 gcmetrics;                    // 0x55a0
    uint64_t                                  field_0x55a8;                 // 0x55a8  // observed storage
    uint8_t                                   field_0x55b0[16];             // 0x55b0  // observed storage
    uint8_t                                   field_0x55c0[16];             // 0x55c0  // observed storage
    uint8_t                                   field_0x55d0[16];             // 0x55d0  // observed storage
    uint8_t                                   field_0x55e0[16];             // 0x55e0  // observed storage
    uint8_t                                   field_0x55f0[16];             // 0x55f0  // observed storage
    uint8_t                                   field_0x5600[16];             // 0x5600  // observed storage
    uint8_t                                   field_0x5610[16];             // 0x5610  // observed storage
    uint8_t                                   field_0x5620[16];             // 0x5620  // observed storage
    uint8_t                                   field_0x5630[16];             // 0x5630  // observed storage
    uint8_t                                   field_0x5640[16];             // 0x5640  // observed storage
    uint8_t                                   field_0x5650[16];             // 0x5650  // observed storage
    uint8_t                                   field_0x5660[16];             // 0x5660  // observed storage
    uint64_t                                  field_0x5670;                 // 0x5670  // observed storage
    char  _gap_0x5678[0x8];
    uint8_t                                   field_0x5680[16];             // 0x5680  // observed storage
    uint8_t                                   field_0x5690[16];             // 0x5690  // observed storage
    uint8_t                                   field_0x56a0[16];             // 0x56a0  // observed storage
    uint8_t                                   field_0x56b0[16];             // 0x56b0  // observed storage
    uint8_t                                   field_0x56c0[16];             // 0x56c0  // observed storage
    uint8_t                                   field_0x56d0[16];             // 0x56d0  // observed storage
    uint8_t                                   field_0x56e0[16];             // 0x56e0  // observed storage
    uint64_t                                  field_0x56f0;                 // 0x56f0  // observed storage
    char  _gap_0x56f8[0x8];
    uint8_t                                   field_0x5700[16];             // 0x5700  // observed storage
    uint8_t                                   field_0x5710[16];             // 0x5710  // observed storage
    uint8_t                                   field_0x5720[16];             // 0x5720  // observed storage
    uint8_t                                   field_0x5730[16];             // 0x5730  // observed storage
    uint8_t                                   field_0x5740[16];             // 0x5740  // observed storage
    uint8_t                                   field_0x5750[16];             // 0x5750  // observed storage
    uint8_t                                   field_0x5760[16];             // 0x5760  // observed storage
    uint64_t                                  field_0x5770;                 // 0x5770  // observed storage
    char                                  _gap_0x5778[0x8];
};

// SharedThreads: 2/2 members
struct SharedThreads {
    uint64_t                                  count;                        // 0x0
    RobloxExtraSpace*                         head;                         // 0x8
};

// Shared: 3/3 members
struct Shared {
    SharedThreads                             allThreads;                   // 0x0
    char  _gap_0x10[0x8];
    void*                                     scriptContext;                // 0x18
    int                                       threadCount;                  // 0x20
};

// robloxextraspace: 9/21 members; 12 unnamed observed storage range(s)
struct RobloxExtraSpace {
    RobloxExtraSpace*                         next;                         // 0x0
    Shared*                                   _container;                   // 0x8
    RobloxExtraSpace*                         prev;                         // 0x10
    std::shared_ptr<Shared>                   shared;                       // 0x18
    uint64_t                                  field_0x28;                   // 0x28  // observed storage
    uint64_t                                  field_0x30;                   // 0x30  // observed storage
    uint64_t                                  field_0x38;                   // 0x38  // observed storage
    std::weak_ptr<void>                       actor;                        // 0x40
    std::weak_ptr<void>                       script;                       // 0x50
    std::weak_ptr<const void>                 InstanceDefiningCapabilities; // 0x60
    uint64_t                                  identity;                     // 0x70
    char  _gap_0x78[0x8];
    uint8_t                                   field_0x80[16];               // 0x80  // observed storage
    uint64_t                                  field_0x90;                   // 0x90  // observed storage
    uint64_t                                  field_0x98;                   // 0x98  // observed storage
    uint64_t                                  capabilities;                 // 0xa0
    uint8_t                                   field_0xa8;                   // 0xa8  // observed storage
    uint8_t                                   field_0xa9;                   // 0xa9  // observed storage
    uint8_t                                   field_0xaa;                   // 0xaa  // observed storage
    uint8_t                                   field_0xab;                   // 0xab  // observed storage
    char  _gap_0xac[0x4];
    uint64_t                                  field_0xb0;                   // 0xb0  // observed storage
    uint64_t                                  field_0xb8;                   // 0xb8  // observed storage
};

// SharedExtraSpace: 1/1 members
struct SharedExtraSpace {
    char  _gap_0x0[0x18];
    uintptr_t                                 ScriptContext;                // 0x18
};

// GC_object: 6 recovered slots
struct GC_object {
    uint8_t                                   field_0x0;                    // 0x0  // observed storage
    uint8_t                                   field_0x1;                    // 0x1  // observed storage
    uint8_t                                   field_0x2;                    // 0x2  // observed storage
    char  _gap_0x3[0xd];
    uint64_t                                  field_0x10;                   // 0x10  // observed storage
    uint32_t                                  field_0x18;                   // 0x18  // observed storage
    char  _gap_0x1c[0x4];
    uint64_t                                  field_0x20;                   // 0x20  // observed storage; zero initialization observed
};

// LocVar: 0 recovered slots
struct LocVar {
    char                                  _gap_0x0[0x18];
};


