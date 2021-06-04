import gdb
import colorama
import struct
import subprocess

# https://www.kernel.org/doc/Documentation/x86/x86_64/mm.txt
def is_kptr(ptr) -> bool:
    return ptr > 0xffff800000000000 and ptr < 0xffffffffff600fff

def _check_smp() -> bool:
    mem = gdb.Value(0xffffffff82b71130) # extract from System.map, address of kmem_cache, wa can automate this by parsing /proc/kallsyms  

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