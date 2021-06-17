#!/usr/bin/python3

import gdb
import colorama
import struct

import sys
sys.path.insert(1, '../')
# 1 ? ¯\_(ツ)_/¯
import check_opt

# Links:
# https://translate.google.com/translate?hl=&sl=auto&tl=en&u=https%3A%2F%2Fzhuanlan.zhihu.com%2Fp%2F103721910
# https://github.com/ulfalizer/Kconfiglib
# https://translate.google.com/translate?hl=&sl=auto&tl=en&u=http%3A%2F%2Fwww.wowotech.net%2Fmemory_management%2F426.html&sandbox=1

kmem_cache = []

# =-=-=-=-=-=-=-=-=-=-=-=

SLAB_CONSISTENCY_CHECKS = 0x00000100
SLAB_RED_ZONE = 0x00000400
SLAB_POISON = 0x00000800
SLAB_STORE_USER = 0x00010000
SLAB_DEBUG_OBJECTS = 0x00400000
SLAB_TRACE = 0x00200000
SLAB_DEACTIVATED = 0x10000000
__CMPXCHG_DOUBLE = 0x40000000
__OBJECT_POISON	 = 0x80000000

SLAB_CPU_ACTIVE = 0x0
SLAB_NODE = 0x1
SLAB_CPU_PARTIAL = 0x2

DEBUG = False

def is_set(flags, flag, s_flags=""):
    if flags & flag and len(s_flags):
        print(f" {s_flags} ", end='')
        return True
    elif flags & flag:
        return True

    return False
    
def sread_memory(addr, length, pack_64=False):
    try:
        inferior = gdb.selected_inferior()
    except RuntimeError:
        return
    if not inferior or not inferior.is_valid():
        return
    if pack_64:
        return int.from_bytes(inferior.read_memory(addr, length), 'little')

    return int.from_bytes(inferior.read_memory(addr, length), 'big')

def kmemcache_from_chunk(chunk):
    return chunk_from_addr(chunk)[1]    

def pagedesc_from_chunk(chunk):
    return chunk_from_addr(chunk)[2]

def is_allocated(chunk):
    return chunk in freelist_slab(kmemcache_from_chunk(chunk), pagedesc_from_chunk(chunk))

# =-=-=-=-=-=-=-=-=-=-=-=

def dump_page_node(page):
    """
    returns informations about a node slab onto the page descriptor
    """

    """
        struct page \{
            .lru = \{
                .next = {},
                .prev = {}
            \},
            .freelist = {},
            .inuse = {}
            [...]
        \}
    """

    s = "--=-=-= kmem_cache.node.partial =-=-=--\n"
    s += f"struct page @ {page}" +  " {\n"
    s += f"\t.flags = {page['flags']},\n"
    s += f"\t.frozen = {page['frozen']},\n"
    s += f"\t.inuse = {page['inuse']},\n"
    s += f"\t.freelist = {page['freelist']},\n"
    s += "\t.lru = {\n"
    s += f"\t\t.next = {page['lru']['next']},"
    s += f"\t\t.prev = {page['lru']['prev']},"
    s += "\t},"
    s += "}"

def dump_pagecpu_active(page):
    """
    returns informations about a node slab onto the page descriptor
    """

    s = "--=-=-= kmem_cache.cpu_slab.page =-=-=--\n"
    s +=  f"struct page @ {page}" +  " {\n"
    s += f"\t.flags = {page['flags']},\n"
    s += f"\t.inuse = {page['inuse']},\n"
    s += f"\t.frozen = {page['frozen']},\n"
    s += f"\t.slab_cache = {page['slab_cache']},\n"
    s += f"\t.freelist = NULL\n"
    s += "}"

    return s

# =-=-=-=-=-=-=-=-=-=-=-=

def valid_kmem_cache(mem):
    cast_mem = gdb.Value(mem).cast(gdb.lookup_type('struct kmem_cache').pointer())
    for name, field in gdb.types.deep_items(gdb.lookup_type('struct kmem_cache')):
        if field.type.code == gdb.TYPE_CODE_PTR and not check_opt.is_kptr(cast_mem[name]) and name != 'cpu_slab':
            return False
    return True

def valid_kmem_cache() -> int:
    """
    returns the address of a valid kmem_cache
    """

    return [int(cache) for cache in kmem_cache if valid_kmem_cache(cache)][0]

# =-=-=-=-=-=-=-=-=-=-=-=

def flags_kmemcache(kmem_cache):
    """
    checks flags
    """
    is_set(int(kmem_cache['flags']), SLAB_RED_ZONE, s_flags="SLAB_RED_ZONE")
    is_set(int(kmem_cache['flags']), SLAB_CONSISTENCY_CHECKS, s_flags="SLAB_CONSISTENCY_CHECKS")
    is_set(int(kmem_cache['flags']), SLAB_DEBUG_OBJECTS, s_flags="SLAB_DEBUG_OBJECTS")
    is_set(int(kmem_cache['flags']), SLAB_POISON, s_flags="SLAB_POISON")
    is_set(int(kmem_cache['flags']), SLAB_STORE_USER, s_flags="SLAB_STORE_USER")
    is_set(int(kmem_cache['flags']), SLAB_TRACE, s_flags="SLAB_TRACE")
    is_set(int(kmem_cache['flags']), SLAB_DEACTIVATED, s_flags="SLAB_DEACTIVATED")
    is_set(int(kmem_cache['flags']), __CMPXCHG_DOUBLE, s_flags="__CMPXCHG_DOUBLE")
    is_set(int(kmem_cache['flags']), __OBJECT_POISON, s_flags="__OBJECT_POISON")

def info_kmemcache(mem):
    """
    https://elixir.bootlin.com/linux/v5.9.8/source/include/linux/slub_def.h#L83
    """
    kmem_cache_t = gdb.lookup_type(f'struct kmem_cache').pointer()
    kmem_cache = gdb.Value(mem).cast(kmem_cache_t)

    if not valid_kmem_cache(mem):
        print(f"{hex(mem)} is not a valid kmem_cache")
        return -1

    print("--=-=-= kmem_cache =-=-=--")
    print(f"Name: {kmem_cache['name'].string()}")
    print(f"Objsize: {kmem_cache['inuse']}")
    print(f"Objsize with metadata: {kmem_cache['size']}")
    print(f"Obj align: {kmem_cache['align']}")
    print(f"Flags: ", end='')
    flags_kmemcache(kmem_cache)
    print("")
    print(f"offset: {kmem_cache['offset']}")
    print(f"cpu_slab @ {kmem_cache['cpu_slab']}")

    if kmem_cache['red_left_pad']:
        print(f"Left redzone padding size: {kmem_cache['red_left_pad']}")
    else:
        print('No redzone')

# =-=-=-=-=-=-=-=-=-=-=-=

def info_slab_cpu(cpu):
    """
    https://elixir.bootlin.com/linux/v5.9.8/source/include/linux/slub_def.h#L42
    """
    kmem_cache_cpu_t = gdb.lookup_type(f'struct kmem_cache_cpu').pointer()
    cpu = gdb.Value(cpu).cast(kmem_cache_cpu_t)

    print("--=-=-= kmem_cache.cpu_slab =-=-=--")
    print(f"kmem_cache_cpu @ {cpu}")
    print(f"tid: {cpu['tid']}")
    print(dump_pagecpu_active(cpu['page']))

    if is_enabled('CONFIG_SLUB_CPU_PARTIAL'):
        print(f"partial: {cpu['partial']}")

    s_freelist = "".join([" => " + colorama.Fore.LIGHTYELLOW_EX + hex(x) + colorama.Fore.RESET for x in freelist_slab(cpu['page']['slab_cache'], cpu)])

    print(f"Active freelist{s_freelist}")

# =-=-=-=-=-=-=-=-=-=-=-=

class kfreeBP(gdb.Breakpoint):
    def stop(self):
        rdi = int(gdb.parse_and_eval("$rdi").cast(gdb.lookup_type('unsigned long')))
        print(hex(rdi))

# =-=-=-=-=-=-=-=-=-=-=-=

CONFIG_FILENAME = "config"

def is_enabled(opt):
    conf_file = open(CONFIG_FILENAME, 'r').read()
    ret = conf_file.find(opt)
    return ret != -1 and conf_file[conf_file.index(opt)+len(opt)+1:conf_file.index(opt)+len(opt)+2] == 'y'

def offset_of(member: str, s_type: str) -> int:
    """
    https://sourceware.org/gdb/onlinedocs/gdb/Types-In-Python.html
    offset of a field among the structure
    """
    return [field.bitpos for name, field in gdb.types.deep_items(gdb.lookup_type(s_type)) if name == member][0] // 8

# =-=-=-=-=-=-=-=-=-=-=-=

def in_cpuslab_active(cpu_slab, chunk: int) -> bool:
    if not int(cpu_slab['freelist']):
        return False

    if (int(cpu_slab['freelist']) & ~0xfff) != (chunk & ~0xfff):
        return False

    return True

def in_cpuslab_partial(cpu_slab, chunk: int) -> bool:
    page_t = gdb.lookup_type(f'struct page').pointer()
    ulong_t = gdb.lookup_type('unsigned long')

    if is_enabled('CONFIG_SLUB_CPU_PARTIAL'):
        nxt = cpu_slab['partial']['next']
        prev = cpu_slab['partial']['prev']

        while prev != nxt:
            if (gdb.Value(int(nxt) + offset_of("freelist", "struct page")).cast(page_t).dereference().cast(ulong_t) & ~0xfff) != (chunk & ~0xfff):
                nxt = gdb.Value(nxt['next'])
                continue
            return nxt
    
    return False

# =-=-=-=-=-=-=-=-=-=

def in_node(node, chunk: int):
    list_head_t = gdb.lookup_type(f'struct list_head').pointer()
    page_t = gdb.lookup_type(f'struct page').pointer()
    ulong_t = gdb.lookup_type('unsigned long')

    nxt = node['partial']['next']
    prev = node['partial']['prev']

    if is_enabled("CONFIG_SLAB"):
        print("Not supported yet")
        return -1

    while prev != nxt:
        curr_page = gdb.Value(int(nxt.cast(ulong_t)) - offset_of('lru', 'struct page')).cast(page_t)
        if (gdb.Value(int(curr_page) + offset_of("freelist", "struct page")).cast(page_t).dereference().cast(ulong_t) & ~0xfff) != (chunk & ~0xfff):
            nxt = gdb.Value(nxt['next']).cast(list_head_t)
            continue
        return curr_page

    if is_enabled("CONFIG_SLUB_DEBUG"):
        nxt = node['full']['next']
        prev = node['full']['prev']

        while prev != nxt:
            curr_page = gdb.Value(int(nxt.cast(ulong_t)) - offset_of('lru', 'struct page')).cast(page_t)
            if (gdb.Value(int(curr_page) + offset_of("freelist", "struct page")).cast(page_t).dereference().cast(ulong_t) & ~0xfff) != (chunk & ~0xfff):
                nxt = gdb.Value(nxt['next']).cast(list_head_t)
                continue
            return curr_page

    return False

# =-=-=-=-=-=-=-=-=-=

def freelist_slab(kmem_cache, page_slab) -> list:
    if is_enabled("CONFIG_SLAB_FREELIST_HARDENED"):
        return -1

    freelist = []
    fp = page_slab['freelist']

    while fp:
        freelist.append(fp)
        fp = sread_memory(int(fp) + int(kmem_cache['offset']), 8, pack_64=True)

    return freelist

# =-=-=-=-=-=-=-=-=-=

def free_chunk(chunk, kmem_cache):
    t = int(kmem_cache['inuse'])
    curr_color = colorama.Fore.BLUE

    if not is_set(kmem_cache['flags'], SLAB_POISON) and not is_set(kmem_cache['flags'], SLAB_RED_ZONE) and not is_set(kmem_cache['flags'], __OBJECT_POISON) and not is_set(kmem_cache['flags'], SLAB_STORE_USER):
        for i in range(0, t, 8):
            if i is int(kmem_cache['offset']):
                curr_color = colorama.Fore.WHITE

            if not i % 16:
                print(f"{hex(chunk+i)}:  {curr_color + '0x{0:0{1}x}'.format(sread_memory(chunk+i, length=0x8, pack_64=True), 16) + colorama.Fore.RESET}  ", end='')
            elif i % 16:
                print(f"{curr_color + '0x{0:0{1}x}'.format(sread_memory(chunk+i, length=0x8, pack_64=True), 16) + colorama.Fore.RESET}")
            curr_color = colorama.Fore.BLUE
    else:
        print("Not supported for now")

def get_fp(chunk, kmem_cache):
    """
    returns next free pointer
    """
    return sread_memory(chunk + int(kmem_cache['offset']), 0x8, pack_64=True)

# =-=-=-=-=-=-=-=-=-=

def alloc_chunk(chunk, kmem_cache):
    """
    Analysis for allocated chunk
    """
    if not is_set(kmem_cache['flags'], SLAB_POISON) and not is_set(kmem_cache['flags'], SLAB_RED_ZONE) and not is_set(kmem_cache['flags'], __OBJECT_POISON) and not is_set(kmem_cache['flags'], SLAB_STORE_USER):
        for i in range(0, int(kmem_cache['inuse']), 8):
            if not i % 16:
                print(f"{hex(chunk+i)}:  {colorama.Fore.BLUE + '0x{0:0{1}x}'.format(sread_memory(chunk+i, length=0x8, pack_64=True), 16) + colorama.Fore.RESET}  ", end='')
            elif i % 16:
                print(f"{colorama.Fore.BLUE + '0x{0:0{1}x}'.format(sread_memory(chunk+i, length=0x8, pack_64=True), 16) + colorama.Fore.RESET}")
    else:
        print("Not supported for now")

def parse_chunk(addr: int):
    """
    Prints a few informations about the addr chunk
    """
    page_t = gdb.lookup_type(f'struct page').pointer()
    ulong_t = gdb.lookup_type('unsigned long')

    if not addr:
        return

    node, kmem_cache, slab, kind = chunk_from_addr(addr)

    if not kmem_cache:
        print(f"{hex(addr)} not found !")
        return -1

    info_kmemcache(kmem_cache)

    if kind is SLAB_CPU_ACTIVE:
        print(info_slab_cpu(slab))
    elif kind is SLAB_CPU_PARTIAL:
        print("Not supported for now")
    elif kind is SLAB_NODE:
        print(dump_page_node(slab))

    # =-=-=-=-=-= 

    if not is_allocated(addr):
        # allocated chunk
        print(f"{colorama.Fore.RED} Allocated chunk {colorama.Fore.RESET}")
        alloc_chunk(addr, kmem_cache)
    else:
        # free chunk
        print(f"{colorama.Fore.GREEN} Free chunk, fp: {hex(get_fp(addr, kmem_cache))} {colorama.Fore.RESET}")
        free_chunk(addr, kmem_cache)

# =-=-=-=-=-=-=-=-=-=-=

def chunk_from_addr(addr: int) -> list:
    """
    return a tuple: node, kmem_cache, page_slab, kind
                 or None, kmem_cache, page_slab, kind
    """
    kmem_cache_cpu_t = gdb.lookup_type(f'struct kmem_cache_cpu').pointer()
    kmem_cache_node_t = gdb.lookup_type(f'struct kmem_cache_node').pointer().pointer() # pointer to a pointer to a struct kmem_cache_node

    for kmem in kmem_cache:
        cpu_slab = kmem['cpu_slab'].cast(kmem_cache_cpu_t)
        node = kmem['node'].cast(kmem_cache_node_t).dereference()

        if in_node(node, addr):
            return node, kmem, in_node(node, addr), SLAB_NODE
        elif in_cpuslab_active(cpu_slab, addr):
            return None, kmem, cpu_slab, SLAB_CPU_ACTIVE
        elif in_cpuslab_partial(cpu_slab, addr):
            return None, kmem, in_cpuslab_partial(cpu_slab, addr), SLAB_CPU_PARTIAL
        continue
    
    return (None, None, None, None)

# =-=-=-=-=-=-=-=-=-=-=-=

def is_list_head(mem) -> bool:
    """
    True if mem, mem['next'] and mem['prev'] are valid pointers
    """
    list_head_t = gdb.lookup_type('struct list_head').pointer()
    tmp_list_head = gdb.Value(mem).cast(list_head_t)

    if check_opt.is_kptr(tmp_list_head) and check_opt.is_kptr(tmp_list_head['next']) and check_opt.is_kptr(tmp_list_head['prev']):
        return True
    
    return False

def is_list_head_kmem(mem, direction='next') -> bool:
    """
    address of the list_head to test
    returns a boolean, True if all the sanity checks succeed else False
    """
    list_head_t = gdb.lookup_type('struct list_head').pointer()
    curr = gdb.Value(mem).cast(list_head_t)
    beg = mem

    if is_list_head(curr):
        while True:
            if is_list_head(curr[direction]):
                curr = curr[direction].cast(list_head_t)
                if int(curr) is beg and direction == 'next':
                    return is_list_head_kmem(mem, direction='prev')
                elif int(curr) is beg and direction == 'prev':
                    return True
            else:
                break

    return False 

def list_head_kmem_cache(mem, offt=0) -> int:
    """
    mem: address of the kmem_cache
    returns the address of the list_head field
    """

    if not is_list_head_kmem(mem):
        # aligned on 4 bytes (more reliable)
        return list_head_kmem_cache(mem+offt, offt=offt+1)

    return mem

# =-=-=-=-=-=-=-=-=-=-=-=

def init_kmem_cache_sym(l=[]) -> list:
    kmalloc_c_type = gdb.lookup_type(f'struct kmem_cache').pointer()
    slab_caches_t = gdb.lookup_type(f'struct list_head').pointer()

    if not len(l):
        nxt = int(gdb.lookup_global_symbol('slab_caches').value().cast(slab_caches_t))
    else:
        nxt = int(l[len(l)-1].cast(kmalloc_c_type)['list']['next'])

    kmem_cache = gdb.Value(int(nxt - ([f.bitpos for f in gdb.lookup_type("struct kmem_cache").fields() if f.name == "list"][0] // 8))).cast(kmalloc_c_type)

    if kmem_cache not in l:
        l.append(kmem_cache)
        if int(kmem_cache['list']['next']) == int(gdb.lookup_global_symbol('slab_caches').value().address):
            return l
        return init_kmem_cache_sym(l)

#===

def init_kmem_cache_nosym(name_fn=None, name_target=None, addr=None) -> list:
    print(f"{name_target}: {hex(addr)}")
    if addr not in kmem_cache and addr:
        kmem_cache.append(addr)

def init_kmem_cache_free(name_fn=None, name_target=None, addr=None) -> list:
    print(f"{name_target}: {hex(addr)}")
    if addr in kmem_cache and addr:
        kmem_cache.remove(addr)

#===

def _full_kmem_cache_init_nosym():
    global kmem_cache

    slab_caches_t = gdb.lookup_type(f'struct list_head').pointer()

    kmem_cache.clear()
    kmem_cache = valid_kmem_cache()
    slab_caches = list_head_kmem_cache(kmem_cache, offt=0)

    offt_list_head = slab_caches - kmem_cache
    beg = slab_caches

    while beg != slab_caches.cast(slab_caches_t)['next']:
        kmem_cache.append(int(slab_caches['next']) - offt_list_head)
        slab_caches = slab_caches['next'].cast(slab_caches_t)

    return kmem_cache

def init_kmem_cache(sym=False):
    if len(kmem_cache) and not sym:
        return _full_kmem_cache_init_nosym()
    if sym:
        _ = [kmem_cache.append(r) for r in init_kmem_cache_sym()]
        return kmem_cache

    print("Warning: This technique is efficient only if you're currently at the begin of the kernel execution")
    print('Hit continue and right after hit ctrl+c to start kheap analysis with the right kmem_cache array')
    check_opt.RawBreakpoint(check_opt.kallsyms_lookup_symbols('__kmem_cache_create')[1], init_kmem_cache_nosym, 'kmem_cache_alloc', 'kmem_cache', '$rdi')
    check_opt.RawBreakpoint(check_opt.kallsyms_lookup_symbols('kmem_cache_destroy')[1], init_kmem_cache_free, 'kmem_cache_destroy', 'kmem_cache', '$rdi')

# =-=-=-=-=-=-=-=-=-=-=-=-=

def check_options():
    for opt, set in check_opt.check_opts(['SMP']).items():
        if set:
            print(f"{opt} enabled !")
            continue
        print(f"{opt} disabled !")

# =-=-=-=-=-=-=-=-=-=-=-=-=

def help():
    print(f'kheap [kmem_cache|chunk|kmem_cache_cpu] addr:\tPrints informations about a particular struct')
    print(f'kheap [kmem_cache|analysis|help]:\t\t\tPrints all the kmem_cache or analyses automatically some structures like kmem_cache')

# We keep this code, who knows ?

# def new_kmalloc_caches() -> list:
#     s = gdb.execute(f'p/d sizeof(kmalloc_caches) / 8', to_string=True)
#     m = int(s[s.find('=')+1:])
#     sum = 0
#     k = 0
#     empty_cache = []

#     while sum < m:
#         s = gdb.execute(f'p/d sizeof(kmalloc_caches[{k}]) / 8', to_string=True)
#         p = int(s[s.find('=')+1:])
#         empty_cache.append([0 for i in range(p)])
#         sum += p
#         k += 1

#     return empty_cache

# def kmem_cache_list() -> list:
#     kmalloc_caches = new_kmalloc_caches()
    
#     kmalloc_c = gdb.lookup_global_symbol('kmalloc_caches').value()
#     kmalloc_c_type = gdb.lookup_type(f'struct kmem_cache').pointer().pointer().pointer()
#     kmalloc_c.cast(kmalloc_c_type)

#     for i in range(len(kmalloc_caches)):
#         for k in range(len(kmalloc_caches[0])):
#             kmalloc_caches[i][k] = kmalloc_c[i][k].cast(gdb.lookup_type('struct kmem_cache').pointer())

#     return kmalloc_caches

# def display_kmem_cache():
#     kmalloc_caches = kmem_cache_list()
#     kmem_cache_t = gdb.lookup_type('struct kmem_cache').pointer()
#     print("Support for 5.8.7 kernel only !")

#     if len(kmalloc_caches) >= 1:
#         kmalloc_normal = kmalloc_caches[0]
#         print("=-= KMALLOC_NORMAL")
#         for kmem_cache in kmalloc_normal[1:]:
#             kmem_cache = kmem_cache.cast(kmem_cache_t)
#             s = f"[{kmem_cache['name'].string()}]: \t{hex(kmem_cache.address)}"
#             print(s)
#     if len(kmalloc_caches) >= 2:
#         kmalloc_reclaim = kmalloc_caches[1]
#         print("=-= KMALLOC_RECLAIM")
#         for kmem_cache in kmalloc_reclaim[1:]:
#             kmem_cache = kmem_cache.cast(kmem_cache_t)
#             s = f"[{kmem_cache['name'].string()}]: \t{hex(kmem_cache.address)}"
#             print(s)
#     if len(kmalloc_caches) >= 3:
#         kmalloc_dma = kmalloc_caches[1]
#         print("=-= KMALLOC_DMA")
#         for kmem_cache in kmalloc_dma[1:]:
#             kmem_cache = kmem_cache.cast(kmem_cache_t)
#             s = f"[{kmem_cache['name'].string()}]: \t{hex(kmem_cache.address)}"
#             print(s)

class kheap(GenericCommand):
    """kernel linux heap stuff."""
    _cmdline_ = "kheap"
    _syntax_  = "{:s}".format(_cmdline_)

    def __init__(self) -> None:
        super().__init__()
        # kfreeBP('kfree', internal=True)

    @only_if_gdb_running # not required, ensures that the debug session is started
    def do_invoke(self, argv):
        if argv[0] == "kmem_cache" and len(argv) == 2:
            info_kmemcache(int(argv[1], 16))
        elif argv[0] == "chunk" and len(argv) == 2:
            parse_chunk(int(argv[1], 16))
        elif argv[0] == "kmem_cache_cpu" and len(argv) == 2:
            info_slab_cpu(int(argv[1], 16))
        elif argv[0] == "kmem_cache":
            _ = [info_kmemcache(f) for f in kmem_cache]
        elif argv[0] == "analysis":
            init_kmem_cache(sym=DEBUG)
            print(kmem_cache)
            # check_options()
        elif argv[0] == "help":
            help()

if __name__ == "__main__":
    register_external_command(kheap())