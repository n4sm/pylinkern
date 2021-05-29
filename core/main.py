#!/usr/bin/python3

from os import X_OK
import gdb
import colorama
import struct
# https://translate.google.com/translate?hl=&sl=auto&tl=en&u=https%3A%2F%2Fzhuanlan.zhihu.com%2Fp%2F103721910

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

    return int.from_bytes(inferior.read_memory(addr, length).tobytes().hex(), 'big')

# =-=-=-=-=-=-=-=-=-=-=-=

def dump_page_node(page):
    list_head_t = gdb.lookup_type(f'struct list_head').pointer()
    ulong_ptr_t = gdb.lookup_type('unsigned long').pointer()
    short_t = gdb.lookup_type('short').pointer()
    base_address = int(page.address)

    # print(f"next: {gdb.Value(base_address + offset_of('lru', 'struct page'))}")

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

    s = f"struct page @ {page}" +  " {\n"
    s += f"\t.flags = {page['flags']},\n"
    s += f"\t.frozen = {page['frozen']},\n"
    s += f"\t.inuse = {page['inuse']},\n"
    s += f"\t.freelist = {page['freelist']},\n"
    s += "\t.lru = {\n"
    s += f"\t\t.next = {page['lru']['next']},"
    s += f"\t\t.prev = {page['lru']['prev']},"
    s += "\t},"
    s += "}"

def dump_page_cpu(page):
    list_head_t = gdb.lookup_type(f'struct list_head').pointer()
    slab_cache_t = gdb.lookup_type(f'struct kmem_cache').pointer()
    ulong_ptr_t = gdb.lookup_type('unsigned long').pointer()
    short_t = gdb.lookup_type('short').pointer()
    base_address = int(page)

    s =  f"struct page @ {page}" +  " {\n"
    s += f"\t.flags = {page['flags']},\n"
    s += f"\t.inuse = {page['inuse']},\n"
    s += f"\t.frozen = {page['frozen']},\n"
    s += f"\t.slab_cache = {page['slab_cache']},\n"
    s += f"\t.freelist = NULL\n"
    s += "}"

    return s

# =-=-=-=-=-=-=-=-=-=-=-=

def flags_kmemcache(kmem_cache):
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
    kmem_cache_t = gdb.lookup_type(f'struct kmem_cache').pointer()
    kmem_cache = gdb.Value(mem).cast(kmem_cache_t)

    print(f"Name: {kmem_cache['name'].string()}")
    print(f"Objsize: {kmem_cache['inuse']}")
    print(f"Objsize with metadata: {kmem_cache['size']}")
    print(f"Obj align: {kmem_cache['align']}")
    print(f"Flags: ", end='')
    flags_kmemcache(kmem_cache)
    print("")
    print(f"Free Pointer offt: {kmem_cache['offset']}")
    print(f"cpu_slab @ {kmem_cache['cpu_slab']}")

    if kmem_cache['red_left_pad']:
        print(f"Left redzone padding size: {kmem_cache['red_left_pad']}")
    else:
        print('No redzone')

# =-=-=-=-=-=-=-=-=-=-=-=

def info_slab_cpu(cpu):
    kmem_cache_cpu_t = gdb.lookup_type(f'struct kmem_cache_cpu').pointer()
    cpu = gdb.Value(cpu).cast(kmem_cache_cpu_t)

    print(f"kmem_cache_cpu @ {cpu}")
    print(f"tid: {cpu['tid']}")
    dump_page_cpu(cpu['page'])

    if is_enabled('CONFIG_SLUB_CPU_PARTIAL'):
        print(f"partial: {cpu['partial']}")

    s_freelist = "".join([" => " + colorama.Fore.LIGHTYELLOW_EX + hex(x) + colorama.Fore.RESET for x in freelist_slab(cpu['page']['slab_cache'], cpu)])

    print(f"Active freelist{s_freelist}")

# =-=-=-=-=-=-=-=-=-=-=-=

class kfreeBP(gdb.Breakpoint):
    def stop(self):
        rdi = int(gdb.parse_and_eval("$rdi").cast(gdb.lookup_type('unsigned long')))
        print(hex(rdi))
        # parse_chunk(rdi)

# =-=-=-=-=-=-=-=-=-=-=-=

CONFIG_FILENAME = ".config"

def is_enabled(opt):
    conf_file = open(CONFIG_FILENAME, 'r').read()
    ret = conf_file.find(opt)
    return ret != -1 and conf_file[conf_file.index(opt)+len(opt)+1:conf_file.index(opt)+len(opt)+2] == 'y'

def offset_of(member: str, s_type: str) -> int:
    return [field.bitpos for name, field in gdb.types.deep_items(gdb.lookup_type(s_type)) if name == member][0] // 8

# =-=-=-=-=-=-=-=-=-=-=-=

def in_cpuslab(cpu_slab, chunk: int) -> bool:
    list_head_t = gdb.lookup_type(f'struct list_head').pointer()
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

    if not int(cpu_slab['freelist']):
        return False

    if (int(cpu_slab['freelist']) & ~0xfff) != (chunk & ~0xfff):
        return False

    return True

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
        print("lol")
        return -1

    freelist = []
    fp = page_slab['freelist']

    while fp:
        freelist.append(fp)
        fp = sread_memory(int(fp) + int(kmem_cache['offset']), 8, pack_64=True)
    
    return freelist

# =-=-=-=-=-=-=-=-=-=

def chunk_metadata(chunk, kmem_cache):
    t = int(kmem_cache['inuse'])
    curr_color = colorama.Fore.BLUE

    if not is_set(kmem_cache['flags'], SLAB_POISON) and not is_set(kmem_cache['flags'], SLAB_RED_ZONE) and not is_set(kmem_cache['flags'], __OBJECT_POISON) and not is_set(kmem_cache['flags'], SLAB_STORE_USER):        
        for i in range(0, t, 8):
            if i is int(kmem_cache['offset']):
                curr_color = colorama.Fore.WHITE

            if not i % 16:
                print(f"{hex(chunk+i*2)}:  {curr_color + '0x{0:0{1}x}'.format(sread_memory(chunk+i, length=0x8, pack_64=True), 16) + colorama.Fore.RESET}  ", end='')
            elif i % 16:
                print(f"{curr_color + '0x{0:0{1}X}'.format(sread_memory(chunk+i, length=0x8, pack_64=True), 16) + colorama.Fore.RESET}")
            curr_color = colorama.Fore.BLUE
    else:
        # for i in range(0, t, 8):
        #         if i % 16:
        #             print(f"{hex(chunk)}:  {colorama.Fore.BLUE + '0x{0:0{1}X}'.format(hex(read_chunk(chunk+i, length=0x8)), 8) + colorama.Fore.RESET}  ", end='')
        #         elif not i % 16:
        #             print(f"{colorama.Fore.BLUE + '0x{0:0{1}X}'.format(hex(read_addr(addr+i, length=0x8)), 8) + colorama.Fore.RESET}")
        print("Not supported for now")

def parse_chunk(addr: int):
    """
    Prints a few informations about the addr chunk
    """
    page_t = gdb.lookup_type(f'struct page').pointer()
    ulong_t = gdb.lookup_type('unsigned long')

    if not addr:
        return

    node, kmem_cache, page_slab = chunk_from_addr(addr)

    if not kmem_cache:
        print(f"{hex(addr)} not found !")
        return -1

    info_kmemcache(kmem_cache)

    if not node:
        # allocated in the cpu_slab
        #print(f"{hex(addr)} belongs to {kmem_cache['name'].string()} @ {(gdb.Value(int(page_slab) + offset_of('freelist', 'struct page')).cast(page_t).dereference().cast(ulong_t) & ~0xfff)} slab")
        print(dump_page_cpu(page_slab))

    if node:
        # allocated in the kmem_cache_node which belongs to the kmem_cache
        #print(f"{hex(addr)} belongs to {kmem_cache['name'].string()} @ {kmem_cache}")
        print(dump_page_node(page_slab))

    # =-=-=-=-=-= 

    chunk_metadata(addr, kmem_cache)

# =-=-=-=-=-=-=-=-=-=-=

def chunk_from_addr(addr: int) -> list:
    """
    return a tuple: node, kmem_cache, page_slab
                or None, kmem_cache, page_slab
    """
    page_t = gdb.lookup_type(f'struct page').pointer()
    kmem_cache_cpu_t = gdb.lookup_type(f'struct kmem_cache_cpu').pointer()
    kmem_cache_node_t = gdb.lookup_type(f'struct kmem_cache_node').pointer().pointer() # pointer to a pointer to a struct kmem_cache_node
    ulong_t = gdb.lookup_type('unsigned long')

    #f = open("log", "a+")

    # print(f"kmem_cache nr: {len(kmem_cache)}")

    for kmem in kmem_cache:
        cpu_slab = kmem['cpu_slab'].cast(kmem_cache_cpu_t)
        node = kmem['node'].cast(kmem_cache_node_t).dereference()

        # print(f"cpu_slab = {cpu_slab}")
        # print(f"node = {node}")

        # print(f"Iterating over kmem={hex(kmem)}, cpu_slab['freelist']={hex(int(cpu_slab['freelist'].cast(ulong_t)) & ~0xfff)}, node={node}")
        # f.write(f"Iterating over kmem={hex(kmem)}, cpu_slab['freelist']={hex(int(cpu_slab['freelist'].cast(ulong_t)) & ~0xfff)}, node={node}\n")

        if in_node(node, addr):
            page = in_node(node, addr)
            #print(f"Chunk {hex(addr)} belongs to {hex(page['freelist'])} freelist")
            #f.write(f"Chunk {hex(addr)} belongs to {hex(page['freelist'])} freelist\n")
            return node, kmem, page
        elif in_cpuslab(cpu_slab, addr):
            #print(f"Chunk {hex(addr)} belongs to {hex(cpu_slab['freelist'])} freelist")
            #f.write(f"Chunk {hex(addr)} belongs to {hex(cpu_slab['freelist'])} freelist\n")
            return None, kmem, cpu_slab['page'].cast(page_t)
        continue
    
    return (None, None, None)

# =-=-=-=-=-=-=-=-=-=-=-=

def kmemcache_from_slabcaches(addr: int) -> int:
    """
    returns the address of the the kmem_cache from which the slab caches belong.
    """
    offset_slab_caches = [f.bitpos for f in gdb.lookup_type("struct kmem_cache").fields() if f.name == "list"][0] // 8
    # offset of slab_caches in kmem_cache

    return addr - offset_slab_caches

def next_kmem_cache(kmem_cache: int) -> int:
    return kmem_cache['list']['next']

def all_kmem_cache(l=[]) -> list:
    kmalloc_c_type = gdb.lookup_type(f'struct kmem_cache').pointer()
    slab_caches_t = gdb.lookup_type(f'struct list_head').pointer()

    if not len(l):
        nxt = int(gdb.lookup_global_symbol('slab_caches').value().cast(slab_caches_t))
    else:
        nxt = int(l[len(l)-1].cast(kmalloc_c_type)['list']['next'])

    kmem_cache = gdb.Value(int(nxt - ([f.bitpos for f in gdb.lookup_type("struct kmem_cache").fields() if f.name == "list"][0] // 8))).cast(kmalloc_c_type)

    if kmem_cache not in l:
        print(hex(kmem_cache))
        print(kmem_cache['name'].string())
        l.append(kmem_cache)
        if int(kmem_cache['list']['next']) == int(gdb.lookup_global_symbol('slab_caches').value().address):
            return l
        return all_kmem_cache(l)

def new_kmalloc_caches() -> list:
    s = gdb.execute(f'p/d sizeof(kmalloc_caches) / 8', to_string=True)
    m = int(s[s.find('=')+1:])
    sum = 0
    k = 0
    empty_cache = []

    while sum < m:
        s = gdb.execute(f'p/d sizeof(kmalloc_caches[{k}]) / 8', to_string=True)
        p = int(s[s.find('=')+1:])
        empty_cache.append([0 for i in range(p)])
        sum += p
        k += 1

    return empty_cache

def kmem_cache_list() -> list:
    kmalloc_caches = new_kmalloc_caches()
    
    kmalloc_c = gdb.lookup_global_symbol('kmalloc_caches').value()
    kmalloc_c_type = gdb.lookup_type(f'struct kmem_cache').pointer().pointer().pointer()
    kmalloc_c.cast(kmalloc_c_type)

    for i in range(len(kmalloc_caches)):
        for k in range(len(kmalloc_caches[0])):
            kmalloc_caches[i][k] = kmalloc_c[i][k].cast(gdb.lookup_type('struct kmem_cache').pointer())

    return kmalloc_caches

def display_kmem_cache():
    kmalloc_caches = kmem_cache_list()
    kmem_cache_t = gdb.lookup_type('struct kmem_cache').pointer()
    print("Support for 5.8.7 kernel only !")

    if len(kmalloc_caches) >= 1:
        kmalloc_normal = kmalloc_caches[0]
        print("=-= KMALLOC_NORMAL")
        for kmem_cache in kmalloc_normal[1:]:
            kmem_cache = kmem_cache.cast(kmem_cache_t)
            s = f"[{kmem_cache['name'].string()}]: \t{hex(kmem_cache.address)}"
            print(s)
    if len(kmalloc_caches) >= 2:
        kmalloc_reclaim = kmalloc_caches[1]
        print("=-= KMALLOC_RECLAIM")
        for kmem_cache in kmalloc_reclaim[1:]:
            kmem_cache = kmem_cache.cast(kmem_cache_t)
            s = f"[{kmem_cache['name'].string()}]: \t{hex(kmem_cache.address)}"
            print(s)
    if len(kmalloc_caches) >= 3:
        kmalloc_dma = kmalloc_caches[1]
        print("=-= KMALLOC_DMA")
        for kmem_cache in kmalloc_dma[1:]:
            kmem_cache = kmem_cache.cast(kmem_cache_t)
            s = f"[{kmem_cache['name'].string()}]: \t{hex(kmem_cache.address)}"
            print(s)

class kheap(GenericCommand):
    """kernel linux heap stuff."""
    _cmdline_ = "kheap"
    _syntax_  = "{:s}".format(_cmdline_)

    def __init__(self) -> None:
        super().__init__()
        kfreeBP('kfree', internal=True)
        _ = [kmem_cache.append(t) for t in all_kmem_cache(l=[])]

    @only_if_gdb_running         # not required, ensures that the debug session is started
    def do_invoke(self, argv):

        if argv[0] == "kmem_cache" and len(argv[1]):
            info_kmemcache(int(argv[1], 16))
        elif argv[0] == "chunk" and len(argv[1]):
            parse_chunk(int(argv[1], 16))
        elif argv[0] == "kmem_cache_cpu" and len(argv[1]):
            info_slab_cpu(int(argv[1], 16))

if __name__ == "__main__":
    register_external_command(kheap())