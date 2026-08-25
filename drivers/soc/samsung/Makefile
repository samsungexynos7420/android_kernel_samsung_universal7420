#
# Exynos SoC Specific drivers
#

obj-$(CONFIG_EXYNOS_CHIPID)	+= exynos-chipid.o

obj-$(CONFIG_ARCH_EXYNOS)	+= exynos-pmu.o exynos-pmu_cal_sys.o
obj-$(CONFIG_ARCH_EXYNOS)	+= exynos-cpu_hotplug.o

ifneq ($(CONFIG_SOC_EXYNOS7580),y)
obj-$(CONFIG_EXYNOS_CONTENT_PATH_PROTECTION) += secmem.o
endif

obj-$(CONFIG_EXYNOS5_SETUP_MIPIPHY)	+= exynos5-mipiphy.o

obj-$(CONFIG_EXYNOS5_DYNAMIC_CPU_HOTPLUG)	+= exynos5_hotplug.o
