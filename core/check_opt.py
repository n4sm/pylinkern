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

def clear():
    gdb.execute('pi import os; os.system(\'clear\')')

# =-=-=-=-=-=-=-=-=-=-=-=--

class RawBreakpoint(gdb.Breakpoint):
    def __init__(self, addr, _u_callback, name):
        self.callback = _u_callback
        self.name = name
        self.addr = addr
        gdb.Breakpoint.__init__(self, "*{}".format(hex(addr)), internal=True)

    def stop(self):
        self.callback(self.name, int(gdb.parse_and_eval("$rdi").cast(gdb.lookup_type('unsigned long'))))
        gdb.Breakpoint.delete(self)

# =-=-=-=-=-=-=-=-=-=-=-=--

def kallsyms_lookup_symbols(sym) -> tuple:
    for l in open(KALLSYMS, 'r').readlines():
        curr_sym = l.split(' ')[2].replace('\n', '')
        type = l.split(' ')[1]
        addr = int(l.split(' ')[0], 16)

        if sym is curr_sym:
            return (type, addr)
    
    return (None, None)

# =-=-=-=-=-=-=-=-=-=-=-=--

def fcomplete_sym(name, addr) -> bool:
    if name + ' ' + hex(addr) + '\n' in open(DMP_SYM, 'a+').readlines():
        return True

    return False

def fsym(name):
    return '\n' + name + ' ' in open(DMP_SYM, 'a+').readlines()

def fsym_replace(name, addr):
    f = open(DMP_SYM, 'w')
    content = f.read()
    offt_beg = content.find('\n' + name + ' ')
    offt_end = content[offt_beg+1].find('\n')
    old_adddr = content[offt_beg+len('\n' + name + ' ')+1:offt_end]
    f.write(content.replace('\n' + name + ' ' + old_adddr, '\n' + name + ' ' + hex(addr)))

def dump_sym(name, addr):
    print(f"{name}: {hex(addr)}")

    # same symbol name but different address
    if fsym(name) and not fcomplete_sym(name):
        print(f"")
        fsym_replace(name, addr)

    # same symbol name & same address
    if fcomplete_sym(name, addr):
        print(f'{name} already in {DMP_SYM} !')
        return

    open(DMP_SYM, 'a+').write(name + ' ' + hex(addr) + '\n')


def hook_sym(name):
    mem = kallsyms_lookup_symbols(name)[1]
    if not mem:
        print(f"{name} not found, abort")
        return None

    RawBreakpoint(mem, dump_sym, name)
    clear()
    print(f'Please trigger {name}, by default the execution will continue.')
    gdb.execute('continue')

def find_sym(name) -> int:
    mem = kallsyms_lookup_symbols(name)[1]
    if mem:
        return mem

    # slow way
    if fsym('kmem_cache'):


    # very slow way
    hook_sym('__kmem_cache_release')

def _check_smp() -> bool:
    mem = gdb.Value(find_sym('kmem_cache'))
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

def recompile(options):
    """
    options: list of option (str)
    """

    f = open('config_append', 'w')
    f.writelines(options)
    f.close()

    subprocess.run(["/usr/bin/make", "-C", ".", "internal"])
    gdb.execute("file build/vmlinux")