/* linux/arch/arm/mach-exynos/setup-fimc-sensor.c
 *
 * Copyright (c) 2014 Samsung Electronics Co., Ltd.
 *		http://www.samsung.com/
 *
 * FIMC-IS-COMPANION gpio and clock configuration
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/gpio.h>
#include <linux/clk.h>
#include <linux/err.h>
#include <linux/platform_device.h>
#include <linux/io.h>
#include <linux/regulator/consumer.h>
#include <linux/delay.h>
#include <linux/clk-provider.h>
#include <linux/clkdev.h>

#include <mach/map.h>
#include <mach/regs-clock.h>

#include <plat/map-s5p.h>
#include <plat/cpu.h>
#ifdef CONFIG_OF
#include <linux/of_gpio.h>
#endif

#include <mach/exynos-fimc-is.h>
#include <mach/exynos-fimc-is-sensor.h>

#if defined(CONFIG_SOC_EXYNOS7420)
int exynos7420_fimc_is_companion_iclk_cfg(struct platform_device *pdev,
	u32 scenario,
	u32 channel)
{
	fimc_is_set_rate_dt(pdev, "dout_clkdiv_pclk_cam1_busperi_167", 167 * 1000000);
	fimc_is_set_rate_dt(pdev, "dout_clkdiv_pclk_cam1_busperi_84", 84 * 1000000);

	return 0;
}

int exynos7420_fimc_is_companion_iclk_on(struct platform_device *pdev,
	u32 scenario,
	u32 channel)
{
	fimc_is_enable(pdev, "mout_user_mux_aclk_cam1_busperi_334");
	fimc_is_enable(pdev, "mout_user_mux_sclk_isp_spi0");
	fimc_is_enable(pdev, "mout_user_mux_sclk_isp_spi1");
	return 0;
}

int exynos7420_fimc_is_companion_iclk_off(struct platform_device *pdev,
	u32 scenario,
	u32 channel)
{
	fimc_is_disable(pdev, "mout_user_mux_aclk_cam1_busperi_334");
	fimc_is_disable(pdev, "mout_user_mux_sclk_isp_spi0");
	fimc_is_disable(pdev, "mout_user_mux_sclk_isp_spi1");
	return 0;
}

int exynos7420_fimc_is_companion_mclk_on(struct platform_device *pdev,
	u32 scenario,
	u32 channel)
{
	char div_name[30];
	char sclk_name[30];

	pr_debug("%s\n", __func__);

	snprintf(div_name, sizeof(div_name), "dout_sclk_isp_sensor%d", channel);
	snprintf(sclk_name, sizeof(sclk_name), "sclk_isp_sensor%d", channel);

	fimc_is_set_rate_dt(pdev, div_name, 24 * 1000000);
	fimc_is_enable_dt(pdev, sclk_name);

	pr_info("%s(%d, mclk : %ld)\n", __func__, channel, fimc_is_get_rate_dt(pdev, sclk_name));

	return 0;
}

int exynos7420_fimc_is_companion_mclk_off(struct platform_device *pdev,
	u32 scenario,
	u32 channel)
{
	char sclk_name[30];

	pr_debug("%s\n", __func__);

	snprintf(sclk_name, sizeof(sclk_name), "sclk_isp_sensor%d", channel);

	fimc_is_disable_dt(pdev, sclk_name);

	return 0;
}
#endif

/* Wrapper functions */
int exynos_fimc_is_companion_iclk_cfg(struct platform_device *pdev,
	u32 scenario,
	u32 channel)
{
#if defined(CONFIG_SOC_EXYNOS7420)
	exynos7420_fimc_is_companion_iclk_cfg(pdev, scenario, channel);
#endif
	return 0;
}

int exynos_fimc_is_companion_iclk_on(struct platform_device *pdev,
	u32 scenario,
	u32 channel)
{
#if defined(CONFIG_SOC_EXYNOS7420)
	exynos7420_fimc_is_companion_iclk_on(pdev, scenario, channel);
#endif
	return 0;
}

int exynos_fimc_is_companion_iclk_off(struct platform_device *pdev,
	u32 scenario,
	u32 channel)
{
#if defined(CONFIG_SOC_EXYNOS7420)
	exynos7420_fimc_is_companion_iclk_off(pdev, scenario, channel);
#endif
	return 0;
}

int exynos_fimc_is_companion_mclk_on(struct platform_device *pdev,
	u32 scenario,
	u32 channel)
{
#if defined(CONFIG_SOC_EXYNOS7420)
	exynos7420_fimc_is_companion_mclk_on(pdev, scenario, channel);
#endif
	return 0;
}

int exynos_fimc_is_companion_mclk_off(struct platform_device *pdev,
	u32 scenario,
	u32 channel)
{
#if defined(CONFIG_SOC_EXYNOS7420)
	exynos7420_fimc_is_companion_mclk_off(pdev, scenario, channel);
#endif
	return 0;
}
