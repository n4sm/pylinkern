import re
from kconfiglib import INT
import gdb
import colorama
import struct
import subprocess

KALLSYMS = "out/mountpoint/kallsyms"
DMP_SYM = "out/sym"

# https://www.kernel.org/doc/Documentation/x86/x86_64/mm.txt
def is_kptr(ptr) -> bool:
    return ptr > 0xffff800000000000 and ptr < 0xffffffffff600fff

# =-=-=-=-=-=-=-=-=-=-=-=--

class RawBreakpoint(gdb.Breakpoint):
    def __init__(self, addr, _u_callback, name):
        self.callback = _u_callback
        self.name = name
        self.addr = addr
        gdb.Breakpoint.__init__(self, "*{}".format(hex(addr)), internal=True)

    def stop(self):
        return self.callback(self.name, int(gdb.parse_and_eval("$rdi").cast(gdb.lookup_type('unsigned long'))))

# =-=-=-=-=-=-=-=-=-=-=-=--

def dump_sym(name, addr):
    print(f"{name}: {hex(addr)}")
    open(DMP_SYM, 'a+').write(name + ' ' + hex(addr) + '\n')

def find_kmem_cache() -> int:
    mem = kallsyms_lookup_symbols('kmem_cache')[1]
    if mem:
        return mem

    # slow way
    mem = kallsyms_lookup_symbols('__kmem_cache_release')[1]
    if not mem:
        print("__kmem_cache_release not found, abort")
        return None

def _check_smp() -> bool:
    mem = gdb.Value(find_kmem_cache())
    if not mem:
        return -1

    kmem_cache_t = gdb.lookup_type(f'struct kmem_cache').pointer()
    kmem_cache = mem.cast(kmem_cache_t)

    return not is_kptr(int(kmem_cache['cpu_slab']))

options_d = {'SMP': _check_smp}

def check_opts(opts: list) -> dict:
    """
    return a dict: {'option': boolean}
    """
    if -1 in [-1 if opt not in options_d.keys() else 0 for opt in opts]:
        return -1

    set_return = {}
    recompile(opts)
    for i in range(len(opts)):
        set_return[opts[i]] = options_d[opts[i]]()

    return set_return

# =-=-=-=-=-=-=-=-=-=-=-=-=-=-=

def kallsyms_lookup_symbols(sym) -> tuple:
    for l in open(KALLSYMS, 'r').readlines():
        curr_sym = l.split(' ')[2].replace('\n', '')
        type = l.split(' ')[1]
        addr = int(l.split(' ')[0], 16)

        if sym is curr_sym:
            return (type, addr)
    
    return (None, None)

# =-=-=-=-=-=-=-=-=-=-=-=-=-=-=

def recompile(options):
    """
    options: list of option (str)
    """

    f = open('config_append', 'w')
    f.writelines(options)
    f.close()

    subprocess.run(["/usr/bin/make", "-C", ".", "internal"])
    gdb.execute("file build/vmlinux")