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
    gdb.execute('pi import subprocess; subprocess.run([\'/usr/bin/clear\'])')

# =-=-=-=-=-=-=-=-=-=-=-=--

class RawBreakpoint(gdb.Breakpoint):
    def __init__(self, addr, _u_callback, name_fn, name_target, reg_arg):
        self.callback = _u_callback
        self.name_fn = name_fn
        self.name_target = name_target
        self.addr = addr
        self.reg_arg = reg_arg
        gdb.Breakpoint.__init__(self, "*{}".format(hex(addr)), internal=True)

    def stop(self):
        self.callback(self.name_fn, self.name_target, int(gdb.parse_and_eval(self.reg_arg).cast(gdb.lookup_type('unsigned long'))))

# =-=-=-=-=-=-=-=-=-=-=-=--

def kallsyms_lookup_symbols(sym) -> tuple:
    for l in open(KALLSYMS, 'r').readlines():
        curr_sym = l.split(' ')[2].replace('\n', '')
        type = l.split(' ')[1]
        addr = int(l.split(' ')[0], 16)

        if sym == curr_sym:
            return (type, addr)
    
    return (None, None)

# =-=-=-=-=-=-=-=-=-=-=-=--

def fcomplete_sym(name, addr) -> bool:
    if name + ' ' + hex(addr) in "".join(open(DMP_SYM, 'r+').readlines()):
        return True

    return False

def fsym(name):
    return name + ' ' in "".join(open(DMP_SYM, 'r+').readlines())

def fsym_replace(name, addr):
    f = open(DMP_SYM, 'w')
    content = f.read()
    offt_beg = content.find(name + ' ')
    offt_end = content[offt_beg].find('\n')
    old_addr = content[offt_beg+len(name + ' ')+1:offt_end]
    f.write(content.replace(name + ' ' + old_addr, name + ' ' + hex(addr)))

def fvalue_sym(name):
    f = open(DMP_SYM, 'r')
    content = f.read()
    offt_beg = content.find(name + ' ')
    offt_end = content[offt_beg].find('\n')
    return int(content[offt_beg+len(name + ' '):offt_end], 16)

def dump_sym(name_fn, name_target, addr):
    print(f"{name_target}: {hex(addr)}")

    # same symbol name but different address
    if fsym(name_target) and not fcomplete_sym(name_target):
        print(f"Updating {name_target}")
        fsym_replace(name_target, addr)
        return

    # same symbol name & same address
    if fcomplete_sym(name_target, addr):
        print(f'{name_target} already in {DMP_SYM} !')
        return

    open(DMP_SYM, 'a+').write(name_target + ' ' + hex(addr) + '\n')

def hook_sym(name_fn, name_target, reg_arg):
    mem = kallsyms_lookup_symbols(name_fn)[1]
    if not mem:
        print(f"{mem} {name_fn} not found, abort")
        return None

    print(f"{name_fn}: {hex(mem)}")
    RawBreakpoint(mem, dump_sym, name_fn, name_target, reg_arg)
    print(f'Please trigger {name_fn}, by default the execution will continue.')
    gdb.execute('continue')

def find_sym(name) -> int:
    mem = kallsyms_lookup_symbols(name)[1]
    if mem:
        return mem

    # slow way
    if fsym(name):
        return fvalue_sym(name)

    # custom technique
    if name == "kmem_cache":
        # very slow way, has to reboot, will not return
        hook_sym('kmem_cache_alloc', 'kmem_cache', '$rdi')

    return -1

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
    # recompile(opts)
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