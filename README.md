## Overview

pylinkern is just a gdb plugin and a kernel dev' & exploit environment. For now there is no stable version.

## Installation

```
$ git clone https://github.com/n4sm/pylinkern.git
$ cd pylinkern/core/sbuild/
$ make install
$ make base
```

## Usage

On a terminal, you have to launch the virtual machine:
```
$ cd pylinkern/core/sbuild/out && ./start.sh
```

On another terminal you can launch gdb:
```
$ cd pylinkern/core/sbuild
$ gdb out/vmlinux
Reading symbols from out/vmlinux...
GEF for linux ready, type `gef' to start, `gef config' to configure
92 commands loaded for GDB 9.2 using Python engine 3.8
gef➤ target remote :1234
...
default_idle () at /media/nasm/7044d811-e1cd-4997-97d5-c08072ce9497/m/dev/python/pylinkern/core/sbuild/src/arch/x86/kernel/process.c:688
688             safe_halt();
gef➤  source ../main.py 
gef➤  kheap help
kheap [chunk|kmem_cache_cpu] addr:              Prints informations about a particular struct
kheap [kmem_cache|analysis|help]:               Prints all the kmem_cache or analyses automatically some structures like kmem_cache
kheap [set sym] true/false:                     Enable or disable symbols support
gef➤  kheap set sym true
gef➤  kheap analysis
gef➤  kheap kmem_cache
...
--=-=-= kmem_cache =-=-=--
Name: kmem_cache
Objsize: 0xc0
Objsize with metadata: 0xc0
Obj align: 0x40
Flags:  __CMPXCHG_DOUBLE 
offset: 0x60
cpu_slab @ 0xffff888007e71020
No redzone
gef➤ kheap kmem_cache_cpu 0xffff888007e71020
--=-=-= kmem_cache.cpu_slab =-=-=--
kmem_cache_cpu @ 0xffff888007e71020
tid: 0x87
--=-=-= kmem_cache.cpu_slab.page =-=-=--
struct page @ 0xffffea00001bcfc0 {
        .flags = 0x4000000000000200,
        .inuse = 0x15,
        .frozen = 0x1,
        .slab_cache = 0xffff888007841000,
        .freelist = NULL
}
Active freelist => 0xffff888006f3f600 => 0xffff888006f3f6c0 => 0xffff888006f3f780 => 0xffff888006f3f840 => 0xffff888006f3f900 => 0xffff888006f3f9c0 => 0xffff888006f3fa80 => 0xffff888006f3fb40 => 0xffff888006f3fc00 => 0xffff888006f3fcc0 => 0xffff888006f3fd80 => 0xffff888006f3fe40 => 0xffff888006f3ff00
gef➤  kheap chunk 0xffff888006f3f600
--=-=-= kmem_cache =-=-=--
Name: kmem_cache
Objsize: 0xc0
Objsize with metadata: 0xc0
Obj align: 0x40
Flags:  __CMPXCHG_DOUBLE 
offset: 0x60
cpu_slab @ 0xffff888007e71020
No redzone
--=-=-= kmem_cache.cpu_slab =-=-=--
kmem_cache_cpu @ 0xffff888007e71020
tid: 0x87
--=-=-= kmem_cache.cpu_slab.page =-=-=--
struct page @ 0xffffea00001bcfc0 {
        .flags = 0x4000000000000200,
        .inuse = 0x15,
        .frozen = 0x1,
        .slab_cache = 0xffff888007841000,
        .freelist = NULL
}
Active freelist => 0xffff888006f3f600 => 0xffff888006f3f6c0 => 0xffff888006f3f780 => 0xffff888006f3f840 => 0xffff888006f3f900 => 0xffff888006f3f9c0 => 0xffff888006f3fa80 => 0xffff888006f3fb40 => 0xffff888006f3fc00 => 0xffff888006f3fcc0 => 0xffff888006f3fd80 => 0xffff888006f3fe40 => 0xffff888006f3ff00
None
 Free chunk, fp: 0xffff888006f3f6c0 
0xffff888006f3f600:  0x0000000000000000  0x0000000000000000
0xffff888006f3f610:  0x0000000000000000  0x0000000000000000
0xffff888006f3f620:  0x0000000000000000  0x0000000000000000
0xffff888006f3f630:  0x0000000000000000  0x0000000000000000
0xffff888006f3f640:  0x0000000000000000  0x0000000000000000
0xffff888006f3f650:  0x0000000000000000  0x0000000000000000
0xffff888006f3f660:  0xffff888006f3f6c0  0x0000000000000000
0xffff888006f3f670:  0x0000000000000000  0x0000000000000000
0xffff888006f3f680:  0x0000000000000000  0x0000000000000000
0xffff888006f3f690:  0x0000000000000000  0x0000000000000000
0xffff888006f3f6a0:  0x0000000000000000  0x0000000000000000
```
