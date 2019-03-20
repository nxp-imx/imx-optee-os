PLATFORM_FLAVOR ?= mx6ulevk

# Get SoC associated with the PLATFORM_FLAVOR
mx6d-flavorlist =
mx6dl-flavorlist = mx6dlsabresd mx6dlsabreauto
mx6q-flavorlist = mx6qsabrelite mx6qsabresd mx6qsabreauto
mx6qp-flavorlist = mx6qpsabresd mx6qpsabreauto
mx6s-flavorlist = mx6solosabresd mx6solosabreauto
mx6sl-flavorlist = mx6slevk
mx6sll-flavorlist = mx6sllevk
mx6sx-flavorlist = mx6sxsabresd mx6sxsabreauto
mx6ul-flavorlist = mx6ulevk mx6ul9x9evk
mx6ull-flavorlist = mx6ullevk
mx7d-flavorlist = mx7dsabresd
mx7s-flavorlist = mx7swarp7
mx7ulp-flavorlist = mx7ulpevk
mx8m-flavorlist = mx8mqevk
mx8mm-flavorlist = mx8mmevk
mx8qm-flavorlist = mx8qmmek mx8qmlpddr4arm2
mx8qx-flavorlist = mx8qxpmek mx8qxplpddr4arm2

ifneq (,$(filter $(PLATFORM_FLAVOR),$(mx6ul-flavorlist)))
$(call force,CFG_MX6,y)
$(call force,CFG_MX6UL,y)
$(call force,CFG_TEE_CORE_NB_CORE,1)
CFG_BUSFREQ ?= y
else ifneq (,$(filter $(PLATFORM_FLAVOR),$(mx6ull-flavorlist)))
$(call force,CFG_MX6,y)
$(call force,CFG_MX6ULL,y)
$(call force,CFG_TEE_CORE_NB_CORE,1)
$(call force,CFG_IMX_CAAM,n)
else ifneq (,$(filter $(PLATFORM_FLAVOR),$(mx6q-flavorlist)))
$(call force,CFG_MX6,y)
$(call force,CFG_MX6Q,y)
$(call force,CFG_TEE_CORE_NB_CORE,4)
CFG_BUSFREQ ?= y
else ifneq (,$(filter $(PLATFORM_FLAVOR),$(mx6qp-flavorlist)))
$(call force,CFG_MX6,y)
$(call force,CFG_MX6QP,y)
$(call force,CFG_TEE_CORE_NB_CORE,4)
# Currently there is a board rework to enable TZASC on i.MX6QP
$(call force,CFG_TZC380,n)
CFG_BUSFREQ ?= y
else ifneq (,$(filter $(PLATFORM_FLAVOR),$(mx6d-flavorlist)))
$(call force,CFG_MX6,y)
$(call force,CFG_MX6D,y)
$(call force,CFG_TEE_CORE_NB_CORE,2)
else ifneq (,$(filter $(PLATFORM_FLAVOR),$(mx6dl-flavorlist)))
$(call force,CFG_MX6,y)
$(call force,CFG_MX6DL,y)
$(call force,CFG_TEE_CORE_NB_CORE,2)
CFG_BUSFREQ ?= y
else ifneq (,$(filter $(PLATFORM_FLAVOR),$(mx6s-flavorlist)))
$(call force,CFG_MX6,y)
$(call force,CFG_MX6S,y)
$(call force,CFG_TEE_CORE_NB_CORE,1)
else ifneq (,$(filter $(PLATFORM_FLAVOR),$(mx6sx-flavorlist)))
$(call force,CFG_MX6,y)
$(call force,CFG_MX6SX,y)
$(call force,CFG_TEE_CORE_NB_CORE,1)
CFG_BUSFREQ ?= y
else ifneq (,$(filter $(PLATFORM_FLAVOR),$(mx6sl-flavorlist)))
$(call force,CFG_MX6,y)
$(call force,CFG_MX6SL,y)
$(call force,CFG_TEE_CORE_NB_CORE,1)
$(call force,CFG_IMX_CAAM,n)
else ifneq (,$(filter $(PLATFORM_FLAVOR),$(mx6sll-flavorlist)))
$(call force,CFG_MX6,y)
$(call force,CFG_MX6SLL,y)
$(call force,CFG_TEE_CORE_NB_CORE,1)
$(call force,CFG_IMX_CAAM,n)
else ifneq (,$(filter $(PLATFORM_FLAVOR),$(mx7d-flavorlist)))
$(call force,CFG_MX7,y)
$(call force,CFG_TEE_CORE_NB_CORE,2)
CFG_BUSFREQ ?= n
else ifneq (,$(filter $(PLATFORM_FLAVOR),$(mx7s-flavorlist)))
$(call force,CFG_MX7,y)
$(call force,CFG_TEE_CORE_NB_CORE,1)
CFG_BUSFREQ ?= n
else ifneq (,$(filter $(PLATFORM_FLAVOR),$(mx7ulp-flavorlist)))
$(call force,CFG_MX7ULP,y)
$(call force,CFG_TEE_CORE_NB_CORE,1)
$(call force,CFG_TZC380,n)
$(call force,CFG_CSU,n)
$(call force,CFG_XRDC,n)
else ifneq (,$(filter $(PLATFORM_FLAVOR),$(mx8m-flavorlist)))
$(call force,CFG_MX8M,y)
$(call force,CFG_ARM64_core,y)
$(call force,CFG_TEE_CORE_NB_CORE,4)
$(call force,CFG_IMX_LPUART,n)
else ifneq (,$(filter $(PLATFORM_FLAVOR),$(mx8mm-flavorlist)))
$(call force,CFG_MX8MM,y)
$(call force,CFG_ARM64_core,y)
$(call force,CFG_TEE_CORE_NB_CORE,4)
$(call force,CFG_IMX_LPUART,n)
else ifneq (,$(filter $(PLATFORM_FLAVOR),$(mx8qm-flavorlist)))
$(call force,CFG_MX8QM,y)
$(call force,CFG_ARM64_core,y)
$(call force,CFG_TEE_CORE_NB_CORE,6)
$(call force,CFG_IMX_CAAM,n)
$(call force,CFG_TZC380,n)
$(call force,CFG_CSU,n)
$(call force,CFG_IMX_UART,n)
$(call force,CFG_IMX_SNVS,n)
$(call force,CFG_WITH_HAB,n)
else ifneq (,$(filter $(PLATFORM_FLAVOR),$(mx8qx-flavorlist)))
$(call force,CFG_MX8QX,y)
$(call force,CFG_ARM64_core,y)
$(call force,CFG_TEE_CORE_NB_CORE,4)
$(call force,CFG_IMX_CAAM,n)
$(call force,CFG_TZC380,n)
$(call force,CFG_CSU,n)
$(call force,CFG_IMX_UART,n)
$(call force,CFG_IMX_SNVS,n)
$(call force,CFG_WITH_HAB,n)
else
$(error Unsupported PLATFORM_FLAVOR "$(PLATFORM_FLAVOR)")
endif

# Generic IMX functionality
$(call force,CFG_GENERIC_BOOT,y)
$(call force,CFG_PM_STUBS,y)
$(call force,CFG_GIC,y)
CFG_CRYPTO_SIZE_OPTIMIZATION ?= n
CFG_WITH_STACK_CANARIES ?= y
CFG_MMAP_REGIONS ?= 24

ifeq ($(CFG_ARM64_core),y)
# arm-v8 platforms
include core/arch/arm/cpu/cortex-armv8-0.mk
$(call force,CFG_WITH_LPAE,y)
$(call force,CFG_WITH_ARM_TRUSTED_FW,y)
$(call force,CFG_ARM_GICV3,y)
$(call force,CFG_SECURE_TIME_SOURCE_CNTPCT,y)
ta-targets = ta_arm64
CFG_CRYPTO_WITH_CE ?= y

CFG_IMX_OCRAM = n
CFG_IMX_WDOG = n
CFG_TZC380 ?= y
CFG_IMX_UART ?= y
CFG_IMX_LPUART ?= y
CFG_IMX_CAAM ?= y
CFG_IMX_SNVS ?= y
CFG_WITH_HAB ?= y
else
# arm-v7 platforms Common definition
ta-targets = ta_arm32

$(call force,CFG_SECURE_TIME_SOURCE_REE,y)
CFG_TZC380 ?= y
CFG_CSU ?= y

ifeq ($(CFG_BUSFREQ),y)
$(call force,CFG_SM_PLATFORM_HANDLER,y)
endif

# i.MX6UL/ULL specific config
ifneq (,$(filter y, $(CFG_MX6UL) $(CFG_MX6ULL)))
include core/arch/arm/cpu/cortex-a7.mk
CFG_IMX_UART ?= y
CFG_TZC380 ?= y
CFG_CSU ?= y
CFG_IMX_CAAM ?= y
CFG_IMX_SNVS ?= y
CFG_WITH_HAB ?= y
$(call force,CFG_BOOT_SYNC_CPU,n)
$(call force,CFG_BOOT_SECONDARY_REQUEST,n)
$(call force,CFG_IMX_LPUART,n)
endif

# i.MX6 Solo/SL/SLL/SoloX/DualLite/Dual/Quad specific config
ifeq ($(filter y, $(CFG_MX6QP) $(CFG_MX6Q) $(CFG_MX6D) $(CFG_MX6DL) \
      $(CFG_MX6S) $(CFG_MX6SX) $(CFG_MX6SL) $(CFG_MX6SLL)), y)
include core/arch/arm/cpu/cortex-a9.mk
$(call force,CFG_MX6,y)
$(call force,CFG_PL310,y)
CFG_PL310_LOCKED ?= y
CFG_IMX_UART ?= y
CFG_TZC380 ?= y
CFG_CSU ?= y
CFG_SCU ?= y
CFG_BOOT_SYNC_CPU ?= y
CFG_BOOT_SECONDARY_REQUEST ?= y
CFG_ENABLE_SCTLR_RR ?= y
CFG_IMX_CAAM ?= y
CFG_IMX_SNVS ?= y
CFG_WITH_HAB ?= y
$(call force,CFG_IMX_LPUART,n)
endif

# i.MX7 specific config
ifeq ($(filter y, $(CFG_MX7)), y)
include core/arch/arm/cpu/cortex-a7.mk
CFG_BOOT_SECONDARY_REQUEST ?= y
CFG_INIT_CNTVOFF ?= y
CFG_IMX_UART ?= y
CFG_TZC380 ?= y
CFG_CSU ?= y
CFG_IMX_CAAM ?= y
CFG_IMX_SNVS ?= y
CFG_WITH_HAB ?= y
$(call force,CFG_IMX_LPUART,n)
endif

# i.MX7ulp specific config
ifeq ($(filter y, $(CFG_MX7ULP)), y)
include core/arch/arm/cpu/cortex-a7.mk
CFG_IMX_LPUART ?= y
$(call force,CFG_BOOT_SECONDARY_REQUEST,n)
CFG_IMX_CAAM ?= y
CFG_WITH_HAB ?= y
$(call force,CFG_IMX_UART,n)
endif

ta-targets = ta_arm32
endif

# Default Board configuration
# set 4M Shared memory
CFG_SHMEM_SIZE ?= 0x00400000

ifneq (,$(filter $(PLATFORM_FLAVOR),mx6ulevk))
CFG_DT ?= y
CFG_NS_ENTRY_ADDR ?= 0x80800000
CFG_DT_ADDR ?= 0x83000000
CFG_DDR_SIZE ?= 0x20000000
CFG_PSCI_ARM32 ?= y
CFG_BOOT_SYNC_CPU = n
CFG_BOOT_SECONDARY_REQUEST = n
CFG_UART_BASE ?= UART1_BASE
endif

ifneq (,$(filter $(PLATFORM_FLAVOR),mx6ul9x9evk))
CFG_DT ?= y
CFG_NS_ENTRY_ADDR ?= 0x80800000
CFG_DT_ADDR ?= 0x83000000
CFG_DDR_SIZE ?= 0x10000000
CFG_PSCI_ARM32 ?= y
CFG_BOOT_SYNC_CPU = n
CFG_BOOT_SECONDARY_REQUEST = n
CFG_UART_BASE ?= UART1_BASE
endif

ifneq (,$(filter $(PLATFORM_FLAVOR),mx6ullevk))
CFG_DT ?= y
CFG_NS_ENTRY_ADDR ?= 0x80800000
CFG_DT_ADDR ?= 0x83000000
CFG_DDR_SIZE ?= 0x20000000
CFG_PSCI_ARM32 ?= y
CFG_BOOT_SYNC_CPU = n
CFG_BOOT_SECONDARY_REQUEST = n
CFG_UART_BASE ?= UART1_BASE
endif

ifneq (,$(filter $(PLATFORM_FLAVOR),mx6qsabrelite))
CFG_DT ?= y
CFG_NS_ENTRY_ADDR ?= 0x12000000
CFG_DT_ADDR ?= 0x18000000
CFG_DDR_SIZE ?= 0x40000000
CFG_PSCI_ARM32 ?= y
CFG_BOOT_SYNC_CPU = n
CFG_BOOT_SECONDARY_REQUEST = y
CFG_UART_BASE ?= UART2_BASE
endif

ifneq (,$(filter $(PLATFORM_FLAVOR),mx6qsabresd))
CFG_DT ?= y
CFG_NS_ENTRY_ADDR ?= 0x12000000
CFG_DT_ADDR ?= 0x18000000
CFG_DDR_SIZE ?= 0x40000000
CFG_PSCI_ARM32 ?= y
CFG_BOOT_SYNC_CPU = n
CFG_BOOT_SECONDARY_REQUEST = y
CFG_UART_BASE ?= UART1_BASE
endif

ifneq (,$(filter $(PLATFORM_FLAVOR),mx6qsabreauto))
CFG_DT ?= y
CFG_NS_ENTRY_ADDR ?= 0x12000000
CFG_DT_ADDR ?= 0x18000000
CFG_DDR_SIZE ?= 0x80000000
CFG_PSCI_ARM32 ?= y
CFG_BOOT_SYNC_CPU = n
CFG_BOOT_SECONDARY_REQUEST = y
CFG_UART_BASE ?= UART4_BASE
endif

ifneq (,$(filter $(PLATFORM_FLAVOR),mx6dlsabresd))
CFG_DT ?= y
CFG_NS_ENTRY_ADDR ?= 0x12000000
CFG_DT_ADDR ?= 0x18000000
CFG_DDR_SIZE ?= 0x40000000
CFG_PSCI_ARM32 ?= y
CFG_BOOT_SYNC_CPU = n
CFG_BOOT_SECONDARY_REQUEST = y
CFG_UART_BASE ?= UART1_BASE
endif

ifneq (,$(filter $(PLATFORM_FLAVOR),mx6dlsabreauto))
CFG_DT ?= y
CFG_NS_ENTRY_ADDR ?= 0x12000000
CFG_DT_ADDR ?= 0x18000000
CFG_DDR_SIZE ?= 0x80000000
CFG_PSCI_ARM32 ?= y
CFG_BOOT_SYNC_CPU = n
CFG_BOOT_SECONDARY_REQUEST = y
CFG_UART_BASE ?= UART4_BASE
endif

ifneq (,$(filter $(PLATFORM_FLAVOR),mx6solosabresd))
CFG_DT ?= y
CFG_NS_ENTRY_ADDR ?= 0x12000000
CFG_DT_ADDR ?= 0x18000000
CFG_DDR_SIZE ?= 0x40000000
CFG_PSCI_ARM32 ?= y
CFG_BOOT_SYNC_CPU = n
CFG_BOOT_SECONDARY_REQUEST = n
CFG_UART_BASE ?= UART1_BASE
endif

ifneq (,$(filter $(PLATFORM_FLAVOR),mx6solosabreauto))
CFG_DT ?= y
CFG_NS_ENTRY_ADDR ?= 0x12000000
CFG_DT_ADDR ?= 0x18000000
CFG_DDR_SIZE ?= 0x80000000
CFG_PSCI_ARM32 ?= y
CFG_BOOT_SYNC_CPU = n
CFG_BOOT_SECONDARY_REQUEST = n
CFG_UART_BASE ?= UART4_BASE
endif

ifneq (,$(filter $(PLATFORM_FLAVOR),mx6qpsabresd))
CFG_DT ?= y
CFG_NS_ENTRY_ADDR ?= 0x12000000
CFG_DT_ADDR ?= 0x18000000
CFG_DDR_SIZE ?= 0x40000000
CFG_PSCI_ARM32 ?= y
CFG_BOOT_SYNC_CPU = n
CFG_BOOT_SECONDARY_REQUEST = y
CFG_UART_BASE ?= UART1_BASE
endif

ifneq (,$(filter $(PLATFORM_FLAVOR),mx6qpsabreauto))
CFG_DT ?= y
CFG_NS_ENTRY_ADDR ?= 0x12000000
CFG_DT_ADDR ?= 0x18000000
CFG_DDR_SIZE ?= 0x80000000
CFG_PSCI_ARM32 ?= y
CFG_BOOT_SYNC_CPU = n
CFG_BOOT_SECONDARY_REQUEST = y
# Currently there is a board rework to enable TZASC on i.MX6QP
CFG_TZC380 = n
CFG_UART_BASE ?= UART4_BASE
endif

ifneq (,$(filter $(PLATFORM_FLAVOR),mx6sxsabresd))
CFG_DT ?= y
CFG_NS_ENTRY_ADDR ?= 0x80800000
CFG_DT_ADDR ?= 0x83000000
CFG_DDR_SIZE ?= 0x40000000
CFG_PSCI_ARM32 ?= y
CFG_BOOT_SYNC_CPU = n
CFG_BOOT_SECONDARY_REQUEST = y
CFG_UART_BASE ?= UART1_BASE
endif

ifneq (,$(filter $(PLATFORM_FLAVOR),mx6sxsabreauto))
CFG_DT ?= y
CFG_NS_ENTRY_ADDR ?= 0x80800000
CFG_DT_ADDR ?= 0x83000000
CFG_DDR_SIZE ?= 0x80000000
CFG_PSCI_ARM32 ?= y
CFG_BOOT_SYNC_CPU = n
CFG_BOOT_SECONDARY_REQUEST = y
CFG_UART_BASE ?= UART1_BASE
endif

ifneq (,$(filter $(PLATFORM_FLAVOR),mx6slevk))
CFG_DT ?= y
CFG_NS_ENTRY_ADDR ?= 0x80800000
CFG_DT_ADDR ?= 0x83000000
CFG_DDR_SIZE ?= 0x40000000
CFG_PSCI_ARM32 ?= y
CFG_BOOT_SYNC_CPU = n
CFG_BOOT_SECONDARY_REQUEST = n
CFG_UART_BASE ?= UART1_BASE
endif

ifneq (,$(filter $(PLATFORM_FLAVOR),mx6sllevk))
CFG_DT ?= y
CFG_NS_ENTRY_ADDR ?= 0x80800000
CFG_DT_ADDR ?= 0x83000000
CFG_DDR_SIZE ?= 0x80000000
CFG_PSCI_ARM32 ?= y
CFG_BOOT_SYNC_CPU = n
CFG_BOOT_SECONDARY_REQUEST = n
CFG_UART_BASE ?= UART1_BASE
endif

ifneq (,$(filter $(PLATFORM_FLAVOR),mx7dsabresd))
CFG_DT ?= y
CFG_NS_ENTRY_ADDR ?= 0x80800000
CFG_DT_ADDR ?= 0x83000000
CFG_DDR_SIZE ?= 0x40000000
CFG_PSCI_ARM32 ?= y
CFG_BOOT_SYNC_CPU = n
CFG_BOOT_SECONDARY_REQUEST = y
CFG_UART_BASE ?= UART1_BASE
endif

ifneq (,$(filter $(PLATFORM_FLAVOR),mx7swarp7))
CFG_DT ?= y
CFG_NS_ENTRY_ADDR ?= 0x80800000
CFG_DT_ADDR ?= 0x83000000
CFG_DDR_SIZE ?= 0x20000000
CFG_DT ?= y
CFG_PSCI_ARM32 ?= y
# TZASC config is not defined for the warp board
CFG_TZC380 = n
CFG_UART_BASE ?= UART1_BASE
endif

ifneq (,$(filter $(PLATFORM_FLAVOR),mx7ulpevk))
CFG_DT ?= y
CFG_NS_ENTRY_ADDR ?= 0x60800000
CFG_DT_ADDR ?= 0x63000000
CFG_DDR_SIZE ?= 0x40000000
CFG_PSCI_ARM32 ?= y
CFG_BOOT_SYNC_CPU = n
CFG_BOOT_SECONDARY_REQUEST = n
CFG_UART_BASE ?= UART4_BASE
endif

ifneq (,$(filter $(PLATFORM_FLAVOR),mx8mqevk))
CFG_DDR_SIZE ?= 0xC0000000
CFG_UART_BASE ?= UART1_BASE
endif

ifneq (,$(filter $(PLATFORM_FLAVOR),mx8mmevk))
CFG_DDR_SIZE ?= 0x80000000
CFG_UART_BASE ?= UART2_BASE
endif

ifneq (,$(filter $(PLATFORM_FLAVOR),mx8qmmek))
CFG_DDR_SIZE ?= 0x80000000
CFG_UART_BASE ?= UART0_BASE
endif

ifneq (,$(filter $(PLATFORM_FLAVOR),mx8qmlpddr4arm2))
CFG_DDR_SIZE ?= 0x80000000
CFG_UART_BASE ?= UART0_BASE
endif

ifneq (,$(filter $(PLATFORM_FLAVOR),mx8qxpmek))
CFG_DDR_SIZE ?= 0x80000000
CFG_UART_BASE ?= UART0_BASE
endif

ifneq (,$(filter $(PLATFORM_FLAVOR),mx8qxplpddr4arm2))
CFG_DDR_SIZE ?= 0x80000000
CFG_UART_BASE ?= UART0_BASE
endif

ifeq ($(filter y, $(CFG_PSCI_ARM32)), y)
CFG_HWSUPP_MEM_PERM_WXN = n
CFG_IMX_WDOG ?= y
$(call force,CFG_IMX_OCRAM,y)
endif

ifeq ($(CFG_IMX_CAAM),y)
# currently disable the use of CAAM in OP-TEE
CFG_IMXCRYPT ?= n

# Cryptographic configuration
include core/arch/arm/plat-imx/crypto_conf.mk
else
$(call force,CFG_IMXCRYPT,n)
$(call force,CFG_WITH_SOFTWARE_PRNG,y)
endif

