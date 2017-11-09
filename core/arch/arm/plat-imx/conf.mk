PLATFORM_FLAVOR ?= mx6ulevk

# Get SoC associated with the PLATFORM_FLAVOR
mx6ul-flavorlist = mx6ulevk mx6ul9x9evk
mx6ull-flavorlist = mx6ullevk
mx6q-flavorlist = mx6qsabrelite mx6qsabresd mx6qsabreauto
mx6d-flavorlist =
mx6dl-flavorlist = mx6dlsabresd mx6dlsabreauto
mx6s-flavorlist =
mx6qp-flavorlist = mx6qpsabresd mx6qpsabreauto
mx6sx-flavorlist = mx6sxsabresd mx6sxsabreauto
mx7-flavorlist = mx7dsabresd

ifneq (,$(filter $(PLATFORM_FLAVOR),$(mx6ul-flavorlist)))
$(call force,CFG_MX6,y)
$(call force,CFG_MX6UL,y)
$(call force,CFG_IMX_UART,y)
$(call force,CFG_IMX_OCRAM,y)
CFG_TEE_CORE_NB_CORE ?= 1

else ifneq (,$(filter $(PLATFORM_FLAVOR),$(mx6ull-flavorlist)))
$(call force,CFG_MX6,y)
$(call force,CFG_MX6ULL,y)
$(call force,CFG_IMX_UART,y)
$(call force,CFG_IMX_OCRAM,y)
CFG_TEE_CORE_NB_CORE ?= 1

else ifneq (,$(filter $(PLATFORM_FLAVOR),$(mx6qp-flavorlist)))
$(call force,CFG_MX6,y)
$(call force,CFG_MX6QP,y)
$(call force,CFG_IMX_UART,y)
$(call force,CFG_IMX_OCRAM,y)
$(call force,CFG_TZC380,n)
CFG_TEE_CORE_NB_CORE ?= 4

else ifneq (,$(filter $(PLATFORM_FLAVOR),$(mx6q-flavorlist)))
$(call force,CFG_MX6,y)
$(call force,CFG_MX6Q,y)
$(call force,CFG_IMX_UART,y)
$(call force,CFG_IMX_OCRAM,y)
CFG_TEE_CORE_NB_CORE ?= 4

else ifneq (,$(filter $(PLATFORM_FLAVOR),$(mx6d-flavorlist)))
$(call force,CFG_MX6,y)
$(call force,CFG_MX6D,y)
$(call force,CFG_IMX_UART,y)
$(call force,CFG_IMX_OCRAM,y)
CFG_TEE_CORE_NB_CORE ?= 2

else ifneq (,$(filter $(PLATFORM_FLAVOR),$(mx6dl-flavorlist)))
$(call force,CFG_MX6,y)
$(call force,CFG_MX6DL,y)
$(call force,CFG_IMX_UART,y)
$(call force,CFG_IMX_OCRAM,y)
CFG_TEE_CORE_NB_CORE ?= 2

else ifneq (,$(filter $(PLATFORM_FLAVOR),$(mx6s-flavorlist)))
$(call force,CFG_MX6,y)
$(call force,CFG_MX6S,y)
$(call force,CFG_IMX_UART,y)
$(call force,CFG_IMX_OCRAM,y)
CFG_TEE_CORE_NB_CORE ?= 1

else ifneq (,$(filter $(PLATFORM_FLAVOR),$(mx6sx-flavorlist)))
$(call force,CFG_MX6,y)
$(call force,CFG_MX6SX,y)
$(call force,CFG_IMX_UART,y)
$(call force,CFG_IMX_OCRAM,y)
CFG_TEE_CORE_NB_CORE ?= 1

else ifneq (,$(filter $(PLATFORM_FLAVOR),$(mx7-flavorlist)))
$(call force,CFG_MX7,y)
$(call force,CFG_IMX_UART,y)
$(call force,CFG_IMX_OCRAM,y)
# TODO: Fix this is not correct 7s is a single core
CFG_TEE_CORE_NB_CORE ?= 2
else
$(error Unsupported PLATFORM_FLAVOR "$(PLATFORM_FLAVOR)")
endif

# Generic IMX functionality
$(call force,CFG_GENERIC_BOOT,y)
$(call force,CFG_PM_STUBS,y)
CFG_IMX_WDOG ?= y

# arm-v7 platforms
# Common definition
core_arm32-platform-aflags	+= -mfpu=neon

ta-targets = ta_arm32

$(call force,CFG_GIC,y)
$(call force,CFG_WITH_SOFTWARE_PRNG,y)
# set TIME to be REE for all platform
$(call force,CFG_SECURE_TIME_SOURCE_REE,y)
CFG_DT ?= y
CFG_PSCI_ARM32 ?= y
CFG_BOOT_SYNC_CPU ?= n
# set CFG_BOOT_SECONDARY_REQUEST to y even for the single cpu. This should not have impact.
CFG_BOOT_SECONDARY_REQUEST ?= y
# No paging support
CFG_PAGEABLE_ADDR ?= 0
CFG_TZC380 ?= y
CFG_CSU ?= y
# i.MX6UL/ULL specific config
ifneq (,$(filter y, $(CFG_MX6UL) $(CFG_MX6ULL)))
include core/arch/arm/cpu/cortex-a7.mk
$(call force,CFG_MX6,y)
endif

# i.MX6 Solo/DualLite/Dual/Quad specific config
ifeq ($(filter y, $(CFG_MX6QP) $(CFG_MX6Q) $(CFG_MX6D) $(CFG_MX6DL) $(CFG_MX6S) \
      $(CFG_MX6SX)), y)
include core/arch/arm/cpu/cortex-a9.mk
$(call force,CFG_MX6,y)
$(call force,CFG_PL310,y)
$(call force,CFG_PL310_LOCKED,y)
CFG_SCU ?= y
CFG_ENABLE_SCTLR_RR ?= y
endif

# i.MX7 specific config
ifeq ($(filter y, $(CFG_MX7)), y)
include core/arch/arm/cpu/cortex-a7.mk
CFG_INIT_CNTVOFF ?= y
endif

# default DDR Config
ifneq (,$(filter $(PLATFORM_FLAVOR),mx6ulevk))
CFG_NS_ENTRY_ADDR ?= 0x80800000
CFG_DT_ADDR ?= 0x83000000
CFG_DDR_SIZE ?= 0x40000000
endif

ifneq (,$(filter $(PLATFORM_FLAVOR),mx6ul9x9evk))
CFG_NS_ENTRY_ADDR ?= 0x80800000
CFG_DT_ADDR ?= 0x83000000
CFG_DDR_SIZE ?= 0x40000000
endif

ifneq (,$(filter $(PLATFORM_FLAVOR),mx6ullevk))
CFG_NS_ENTRY_ADDR ?= 0x80800000
CFG_DT_ADDR ?= 0x83000000
CFG_DDR_SIZE ?= 0x40000000
endif

ifneq (,$(filter $(PLATFORM_FLAVOR),mx6qsabrelite))
CFG_NS_ENTRY_ADDR ?= 0x12000000
CFG_DT_ADDR ?= 0x18000000
CFG_DDR_SIZE ?= 0x40000000
endif

ifneq (,$(filter $(PLATFORM_FLAVOR),mx6qsabresd))
CFG_NS_ENTRY_ADDR ?= 0x12000000
CFG_DT_ADDR ?= 0x18000000
CFG_DDR_SIZE ?= 0x40000000
endif

ifneq (,$(filter $(PLATFORM_FLAVOR),mx6qsabreauto))
CFG_NS_ENTRY_ADDR ?= 0x12000000
CFG_DT_ADDR ?= 0x18000000
CFG_DDR_SIZE ?= 0x80000000
endif

ifneq (,$(filter $(PLATFORM_FLAVOR),mx6dlsabresd))
CFG_NS_ENTRY_ADDR ?= 0x12000000
CFG_DT_ADDR ?= 0x18000000
CFG_DDR_SIZE ?= 0x40000000
endif

ifneq (,$(filter $(PLATFORM_FLAVOR),mx6dlsabreauto))
CFG_NS_ENTRY_ADDR ?= 0x12000000
CFG_DT_ADDR ?= 0x18000000
CFG_DDR_SIZE ?= 0x80000000
endif

ifneq (,$(filter $(PLATFORM_FLAVOR),mx6qpsabresd))
CFG_NS_ENTRY_ADDR ?= 0x12000000
CFG_DT_ADDR ?= 0x18000000
CFG_DDR_SIZE ?= 0x40000000
endif

ifneq (,$(filter $(PLATFORM_FLAVOR),mx6qpsabreauto))
CFG_NS_ENTRY_ADDR ?= 0x12000000
CFG_DT_ADDR ?= 0x18000000
CFG_DDR_SIZE ?= 0x80000000
endif

ifneq (,$(filter $(PLATFORM_FLAVOR),mx6sxsabresd))
CFG_NS_ENTRY_ADDR ?= 0x80800000
CFG_DT_ADDR ?= 0x83000000
CFG_DDR_SIZE ?= 0x40000000
endif

ifneq (,$(filter $(PLATFORM_FLAVOR),mx6sxsabreauto))
CFG_NS_ENTRY_ADDR ?= 0x80800000
CFG_DT_ADDR ?= 0x83000000
CFG_DDR_SIZE ?= 0x80000000
endif

ifneq (,$(filter $(PLATFORM_FLAVOR),mx7dsabresd))
CFG_NS_ENTRY_ADDR ?= 0x80800000
CFG_DT_ADDR ?= 0x83000000
CFG_DDR_SIZE ?= 0x40000000
endif

ifeq ($(filter y, $(CFG_PSCI_ARM32)), y)
CFG_HWSUPP_MEM_PERM_WXN = n
CFG_IMX_WDOG ?= y
endif

CFG_MMAP_REGIONS ?= 24
CFG_CRYPTO_SIZE_OPTIMIZATION ?= n
CFG_WITH_STACK_CANARIES ?= y

ta-targets = ta_arm32
