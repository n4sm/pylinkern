from kconfiglib import Kconfig, Symbol, Choice, MENU, COMMENT
import sys 

TRUE = 2
FALSE = 0

CONFIG_FILE =  "../config"
KCONFIG_FILE = "Kconfig"
DEFCONFIG = "../defconfig"

DEBUG_CONF = ['DEBUG_KERNEL', 'DEBUG_INFO', 'GDB_SCRIPTS']

def is_yes(kconf, opt):
    return kconf.syms[opt].visibility == 2

def is_no(kconf, opt):
    return kconf.syms[opt].visibility == 0

def may_yes(kconf, opt):
    if kconf.syms[opt].assignable:
        return 2 in kconf.syms[opt].assignable

def may_no(kconf, opt):
    if kconf.syms[opt].assignable:
        return 0 in kconf.syms[opt].assignable

#      |  assignable:
#      |    A tuple containing the tristate user values that can currently be
#      |    assigned to the symbol (that would be respected), ordered from lowest (0,
#      |    representing n) to highest (2, representing y). This corresponds to the
#      |    selections available in the menuconfig interface. The set of assignable
#      |    values is calculated from the symbol's visibility and selects/implies.
#      |  
#      |    Returns the empty set for non-bool/tristate symbols and for symbols with
#      |    visibility n. The other possible values are (0, 2), (0, 1, 2), (1, 2),
#      |    (1,), and (2,). A (1,) or (2,) result means the symbol is visible but
#      |    "locked" to m or y through a select, perhaps in combination with the
#      |    visibility. menuconfig represents this as -M- and -*-, respectively.
#      |  
#      |    For string/hex/int symbols, check if Symbol.visibility is non-0 (non-n)
#      |    instead to determine if the value can be changed.
#      |  
#      |    Some handy 'assignable' idioms:
#      |  
#      |      # Is 'sym' an assignable (visible) bool/tristate symbol?
#      |      if sym.assignable:
#      |          # What's the highest value it can be assigned? [-1] in Python
#      |          # gives the last element.
#      |          sym_high = sym.assignable[-1]
#      |  
#      |          # The lowest?
#      |          sym_low = sym.assignable[0]
#      |  
#      |          # Can the symbol be set to at least m?
#      |          if sym.assignable[-1] >= 1:
#      |              ...
#      |  
#      |      # Can the symbol be set to m?
#      |      if 1 in sym.assignable:
#      |          ...
#      |  
#      |  visibility:
#      |    The visibility of the symbol. One of 0, 1, 2, representing n, m, y. See
#      |    the module documentation for an overview of symbol values and visibility.

# =-=-=-=-=-=-=-=-=-=---

# menuconfig NET_9P
# 	depends on NET
# 	tristate "Plan 9 Resource Sharing Support (9P2000)"
# 	help
# 	  If you say Y here, you will get experimental support for
# 	  Plan 9 resource sharing via the 9P2000 protocol.

# 	  See <http://v9fs.sf.net> for more information.

# 	  If unsure, say N.

# if NET_9P

# config NET_9P_VIRTIO
# 	depends on VIRTIO
# 	tristate "9P Virtio Transport"
# 	help
# 	  This builds support for a transports between
# 	  guest partitions and a host partition.

# config NET_9P_XEN
# 	depends on XEN
# 	select XEN_XENBUS_FRONTEND
# 	tristate "9P Xen Transport"
# 	help
# 	  This builds support for a transport for 9pfs between
# 	  two Xen domains.


# config NET_9P_RDMA
# 	depends on INET && INFINIBAND && INFINIBAND_ADDR_TRANS
# 	tristate "9P RDMA Transport (Experimental)"
# 	help
# 	  This builds support for an RDMA transport.

# config NET_9P_DEBUG
# 	bool "Debug information"
# 	help
# 	  Say Y if you want the 9P subsystem to log debug information.

# endif

_9P_CONF = ['NET_9P', 'VIRTIO_PCI', 'VIRTIO', 'NET_9P_VIRTIO', 'NET_9P_XEN', 'NET_9P_RDMA', 'NET_9P_DEBUG', '9P_FS', '9P_FS_POSIX_ACL', '9P_FS_SECURITY']

def enable_opt(kconf, opt):
    kconf.syms[opt].set_value(TRUE)

def disable_opt(kconf, opt):
    if not may_no(kconf, opt) and not is_no(kconf, opt):
        return -1

    if not is_no(kconf, opt):
        kconf.syms[opt].set_value(FALSE)

def set_debug(kconf):
    for opt in DEBUG_CONF:
        enable_opt(kconf, opt)

def set_9p(kconf):
    for opt in _9P_CONF:
        enable_opt(kconf, opt)

def main():
    kconf = Kconfig(KCONFIG_FILE, warn=False)
    kconf.load_config(DEFCONFIG)

    if sys.argv[1] == "GDB_INTERNAL":
        try:
            for opt in open("../config_append", "r").readlines():
                enable_opt(kconf, opt)
        except:
            pass

    set_debug(kconf)
    disable_opt(kconf, 'SMP')
    # enable_opt(kconf, 'BLK_DEV_INITRD')
    # enable_opt(kconf, 'BLK_DEV_RAM')
    kconf.write_config(CONFIG_FILE)

main()