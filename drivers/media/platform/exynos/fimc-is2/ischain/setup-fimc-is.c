/* linux/arch/arm/mach-exynos/setup-fimc-is.c
 *
 * Copyright (c) 2011 Samsung Electronics Co., Ltd.
 *		http://www.samsung.com/
 *
 * FIMC-IS gpio and clock configuration
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
#include <exynos-fimc-is.h>
#ifdef CONFIG_OF
#include <linux/of_gpio.h>
#endif

struct platform_device; /* don't need the contents */

/*------------------------------------------------------*/
/*		Common control				*/
/*------------------------------------------------------*/

#define PRINT_CLK(c, n) pr_info("%s : 0x%08X\n", n, readl(c));

int exynos_fimc_is_print_cfg(struct platform_device *pdev, u32 channel)
{
	pr_debug("%s\n", __func__);

	return 0;
}

/* utility function to set rate with DT */
int fimc_is_set_rate(struct platform_device *pdev,
	const char *conid, unsigned int rate)
{
	int ret = 0;
	int id;
	struct clk *target;

	for ( id = 0; id < CLK_NUM; id++ ) {
		if (!strcmp(conid, clk_g_list[id]))
			target = clk_target_list[id];
	}

	if (IS_ERR_OR_NULL(target)) {
		pr_err("%s: clk_target_list is NULL : %s\n", __func__, conid);
		return -EINVAL;
	}

	ret = clk_set_rate(target, rate);
	if (ret) {
		pr_err("%s: clk_set_rate is fail(%s)\n", __func__, conid);
		return ret;
	}

	/* fimc_is_get_rate_dt(pdev, conid); */

	return 0;
}

/* utility function to get rate with DT */
ulong fimc_is_get_rate(struct platform_device *pdev,
	const char *conid)
{
	int id;
	struct clk *target;
	ulong rate_target;

	for ( id = 0; id < CLK_NUM; id++ ) {
		if (!strcmp(conid, clk_g_list[id]))
			target = clk_target_list[id];
	}

	if (IS_ERR_OR_NULL(target)) {
		pr_err("%s: clk_target_list is NULL : %s\n", __func__, conid);
		return -EINVAL;
	}

	rate_target = clk_get_rate(target);
	pr_info("%s : %ldMhz\n", conid, rate_target/1000000);

	return rate_target;
}

/* utility function to eable with DT */
int  fimc_is_enable(struct platform_device *pdev,
	const char *conid)
{
	int ret;
	int id;
	struct clk *target;

	for ( id = 0; id < CLK_NUM; id++ ) {
		if (!strcmp(conid, clk_g_list[id]))
			target = clk_target_list[id];
	}

	if (IS_ERR_OR_NULL(target)) {
		pr_err("%s: clk_target_list is NULL : %s\n", __func__, conid);
		return -EINVAL;
	}

	ret = clk_prepare(target);
	if (ret) {
		pr_err("%s: clk_prepare is fail(%s)\n", __func__, conid);
		return ret;
	}

	ret = clk_enable(target);
	if (ret) {
		pr_err("%s: clk_enable is fail(%s)\n", __func__, conid);
		return ret;
	}

	return 0;
}

/* utility function to disable with DT */
int fimc_is_disable(struct platform_device *pdev,
	const char *conid)
{
	int id;
	struct clk *target;

	for ( id = 0; id < CLK_NUM; id++ ) {
		if (!strcmp(conid, clk_g_list[id]))
			target = clk_target_list[id];
	}

	if (IS_ERR_OR_NULL(target)) {
		pr_err("%s: clk_target_list is NULL : %s\n", __func__, conid);
		return -EINVAL;
	}

	clk_disable(target);
	clk_unprepare(target);

	return 0;
}

/* utility function to set parent with DT */
int fimc_is_set_parent_dt(struct platform_device *pdev,
	const char *child, const char *parent)
{
	int ret = 0;
	struct clk *p;
	struct clk *c;

	p = clk_get(&pdev->dev, parent);
	if (IS_ERR_OR_NULL(p)) {
		pr_err("%s: could not lookup clock : %s\n", __func__, parent);
		return -EINVAL;
	}

	c = clk_get(&pdev->dev, child);
	if (IS_ERR_OR_NULL(c)) {
		pr_err("%s: could not lookup clock : %s\n", __func__, child);
		return -EINVAL;
	}

	ret = clk_set_parent(c, p);
	if (ret) {
		pr_err("%s: clk_set_parent is fail(%s -> %s)\n", __func__, child, parent);
		return ret;
	}

	return 0;
}

/* utility function to set rate with DT */
int fimc_is_set_rate_dt(struct platform_device *pdev,
	const char *conid, unsigned int rate)
{
	int ret = 0;
	struct clk *target;

	target = clk_get(&pdev->dev, conid);
	if (IS_ERR_OR_NULL(target)) {
		pr_err("%s: could not lookup clock : %s\n", __func__, conid);
		return -EINVAL;
	}

	ret = clk_set_rate(target, rate);
	if (ret) {
		pr_err("%s: clk_set_rate is fail(%s)\n", __func__, conid);
		return ret;
	}

	/* fimc_is_get_rate_dt(pdev, conid); */

	return 0;
}

/* utility function to get rate with DT */
ulong fimc_is_get_rate_dt(struct platform_device *pdev,
	const char *conid)
{
	struct clk *target;
	ulong rate_target;

	target = clk_get(&pdev->dev, conid);
	if (IS_ERR_OR_NULL(target)) {
		pr_err("%s: could not lookup clock : %s\n", __func__, conid);
		return -EINVAL;
	}

	rate_target = clk_get_rate(target);
	pr_info("%s : %ldMhz\n", conid, rate_target/1000000);

	return rate_target;
}

/* utility function to eable with DT */
int  fimc_is_enable_dt(struct platform_device *pdev,
	const char *conid)
{
	int ret;
	struct clk *target;

	target = clk_get(&pdev->dev, conid);
	if (IS_ERR_OR_NULL(target)) {
		pr_err("%s: could not lookup clock : %s\n", __func__, conid);
		return -EINVAL;
	}

	ret = clk_prepare(target);
	if (ret) {
		pr_err("%s: clk_prepare is fail(%s)\n", __func__, conid);
		return ret;
	}

	ret = clk_enable(target);
	if (ret) {
		pr_err("%s: clk_enable is fail(%s)\n", __func__, conid);
		return ret;
	}

	return 0;
}

/* utility function to disable with DT */
int fimc_is_disable_dt(struct platform_device *pdev,
	const char *conid)
{
	struct clk *target;

	target = clk_get(&pdev->dev, conid);
	if (IS_ERR_OR_NULL(target)) {
		pr_err("%s: could not lookup clock : %s\n", __func__, conid);
		return -EINVAL;
	}

	clk_disable(target);
	clk_unprepare(target);

	return 0;
}

#if defined(CONFIG_SOC_EXYNOS7420)
int exynos7420_fimc_is_clk_gate(u32 clk_gate_id, bool is_on)
{
	int cfg = 0;
	u32 value = 0;

	if (clk_gate_id == 0)
		return 0;

	/* CAM0 */
	if (clk_gate_id & (1 << FIMC_IS_GATE_3AA1_IP))
		value |= (1 << 1);
	if (clk_gate_id & (1 << FIMC_IS_GATE_3AA0_IP))
		value |= (1 << 0);

	if (value > 0) {
		cfg = readl(EXYNOS7420_ENABLE_IP_CAM00);
		if (is_on)
			writel(cfg | value, EXYNOS7420_ENABLE_IP_CAM00);
		else
			writel(cfg & ~(value), EXYNOS7420_ENABLE_IP_CAM00);
		pr_debug("%s :1 [%s] gate(%d) (0x%x) * (0x%x)\n", __func__,
				is_on ? "ON" : "OFF",
				clk_gate_id,
				cfg,
				value);
	}

	/* ISP 0 */
	value = 0;
	if (clk_gate_id & (1 << FIMC_IS_GATE_ISP_IP))
		value |= (1 << 0);
	if (clk_gate_id & (1 << FIMC_IS_GATE_TPU_IP))
		value |= (1 << 1);

	if (value > 0) {
		cfg = readl(EXYNOS7420_ENABLE_IP_ISP0);
		if (is_on)
			writel(cfg | value, EXYNOS7420_ENABLE_IP_ISP0);
		else
			writel(cfg & ~(value), EXYNOS7420_ENABLE_IP_ISP0);
		pr_debug("%s :2 [%s] gate(%d) (0x%x) * (0x%x)\n", __func__,
				is_on ? "ON" : "OFF",
				clk_gate_id,
				cfg,
				value);
	}

	/* ISP 1 */
	value = 0;
	if (clk_gate_id & (1 << FIMC_IS_GATE_ISP1_IP))
		value |= (1 << 0);

	if (value > 0) {
		cfg = readl(EXYNOS7420_ENABLE_IP_ISP1);
		if (is_on)
			writel(cfg | value, EXYNOS7420_ENABLE_IP_ISP1);
		else
			writel(cfg & ~(value), EXYNOS7420_ENABLE_IP_ISP1);
		pr_debug("%s :3 [%s] gate(%d) (0x%x) * (0x%x)\n", __func__,
				is_on ? "ON" : "OFF",
				clk_gate_id,
				cfg,
				value);
	}

	/* CAM 10 */
	value = 0;
	if (clk_gate_id & (1 << FIMC_IS_GATE_SCP_IP))
		value |= (1 << 2);
	if (clk_gate_id & (1 << FIMC_IS_GATE_VRA_IP))
		value |= (1 << 3);

	if (value > 0) {
		cfg = readl(EXYNOS7420_ENABLE_IP_CAM10);
		if (is_on)
			writel(cfg | value, EXYNOS7420_ENABLE_IP_CAM10);
		else
			writel(cfg & ~(value), EXYNOS7420_ENABLE_IP_CAM10);
		pr_debug("%s :3 [%s] gate(%d) (0x%x) * (0x%x)\n", __func__,
				is_on ? "ON" : "OFF",
				clk_gate_id,
				cfg,
				value);
	}

	return 0;
}

int exynos7420_fimc_is_cfg_clk(struct platform_device *pdev)
{
	pr_debug("%s\n", __func__);

	/*
	 * CAUTION
	 * source clock is top0 source not OSC although USERMUX is disbled
	 * anyway, div config for max can be completed whatever source clock is
	 */

	/* CAM0 */
	fimc_is_set_rate(pdev, "dout_clkdiv_pclk_cam0_bnsa_345", 1);
	fimc_is_set_rate(pdev, "dout_clkdiv_pclk_cam0_bnsb_345", 1);
	fimc_is_set_rate(pdev, "dout_clkdiv_pclk_cam0_bnsd_345", 1);
	fimc_is_set_rate(pdev, "dout_clkdiv_pclk_cam0_3aa0_345", 1);
	fimc_is_set_rate(pdev, "dout_clkdiv_pclk_cam0_3aa1_234", 1);
	fimc_is_set_rate(pdev, "dout_clkdiv_pclk_cam0_trex_266", 1);
	fimc_is_set_rate(pdev, "dout_clkdiv_pclk_cam0_trex_133", 1);

	/* CAM1 */
	fimc_is_set_rate(pdev, "dout_clkdiv_pclk_cam1_sclvra_246", 1);
	fimc_is_set_rate(pdev, "dout_clkdiv_pclk_cam1_arm_167", 1);
	fimc_is_set_rate(pdev, "dout_clkdiv_pclk_cam1_busperi_167", 1);
	fimc_is_set_rate(pdev, "dout_clkdiv_pclk_cam1_busperi_84", 1);

	/* ISP0 */
	fimc_is_set_rate(pdev, "dout_clkdiv_pclk_isp0_isp0_295", 1);
	fimc_is_set_rate(pdev, "dout_clkdiv_pclk_isp0_tpu_295", 1);
	fimc_is_set_rate(pdev, "dout_clkdiv_pclk_isp0_trex_266", 1);
	fimc_is_set_rate(pdev, "dout_clkdiv_pclk_isp0_trex_133", 1);

	/* ISP1 */
	fimc_is_set_rate(pdev, "dout_clkdiv_pclk_isp1_isp1_234", 1);

	return 0;
}

int exynos7420_fimc_is_clk_on(struct platform_device *pdev)
{
	int ret = 0;
	struct exynos_platform_fimc_is *pdata;

	pdata = dev_get_platdata(&pdev->dev);
	if (pdata->clock_on) {
		ret = pdata->clk_off(pdev);
		if (ret) {
			pr_err("clk_off is fail(%d)\n", ret);
			goto p_err;
		}
	}

	/* BUS0 */
	fimc_is_enable(pdev, "gate_aclk_lh_cam0");
	fimc_is_enable(pdev, "gate_aclk_lh_cam1");
	fimc_is_enable(pdev, "gate_aclk_lh_isp");
	fimc_is_enable(pdev, "gate_aclk_noc_bus0_nrt");

	/* CAM0 */
	fimc_is_enable(pdev, "mout_user_mux_aclk_cam0_csis0_690");
	fimc_is_enable(pdev, "mout_user_mux_aclk_cam0_bnsa_690");
	fimc_is_enable(pdev, "mout_user_mux_aclk_cam0_bnsb_690");
	fimc_is_enable(pdev, "mout_user_mux_aclk_cam0_bnsd_690");
	fimc_is_enable(pdev, "mout_user_mux_aclk_cam0_csis1_174");
	fimc_is_enable(pdev, "mout_user_mux_aclk_cam0_3aa0_690");
	fimc_is_enable(pdev, "mout_user_mux_aclk_cam0_3aa1_468");
	fimc_is_enable(pdev, "mout_user_mux_aclk_cam0_trex_532");
	fimc_is_enable(pdev, "mout_user_mux_aclk_cam0_nocp_133");
	fimc_is_enable(pdev, "mout_user_mux_phyclk_rxbyteclkhs0_s2a");
	fimc_is_enable(pdev, "mout_user_mux_phyclk_rxbyteclkhs0_s4");
	fimc_is_enable(pdev, "mout_user_mux_phyclk_rxbyteclkhs1_s4");
	fimc_is_enable(pdev, "mout_user_mux_phyclk_rxbyteclkhs2_s4");
	fimc_is_enable(pdev, "mout_user_mux_phyclk_rxbyteclkhs3_s4");

	fimc_is_set_rate(pdev, "dout_clkdiv_pclk_cam0_bnsa_345", 330 * 1000000);
	fimc_is_set_rate(pdev, "dout_clkdiv_pclk_cam0_bnsb_345", 330 * 1000000);
	fimc_is_set_rate(pdev, "dout_clkdiv_pclk_cam0_bnsd_345", 330 * 1000000);
	fimc_is_set_rate(pdev, "dout_clkdiv_pclk_cam0_3aa0_345", 330 * 1000000);
	fimc_is_set_rate(pdev, "dout_clkdiv_pclk_cam0_3aa1_234", 234 * 1000000);
	fimc_is_set_rate(pdev, "dout_clkdiv_pclk_cam0_trex_266", 266 * 1000000);
	fimc_is_set_rate(pdev, "dout_clkdiv_pclk_cam0_trex_133", 133 * 1000000);

	/* CAM1 */
	fimc_is_enable(pdev, "mout_user_mux_aclk_cam1_sclvra_491");
	fimc_is_enable(pdev, "mout_user_mux_aclk_cam1_arm_668");
	fimc_is_enable(pdev, "mout_user_mux_aclk_cam1_busperi_334");
	fimc_is_enable(pdev, "mout_user_mux_aclk_cam1_bnscsis_133");
	fimc_is_enable(pdev, "mout_user_mux_aclk_cam1_nocp_133");
	fimc_is_enable(pdev, "mout_user_mux_aclk_cam1_trex_532");
	fimc_is_enable(pdev, "mout_user_mux_sclk_isp_spi0");
	fimc_is_enable(pdev, "mout_user_mux_sclk_isp_spi1");
	fimc_is_enable(pdev, "mout_user_mux_sclk_isp_uart");
	fimc_is_enable(pdev, "mout_user_mux_phyclk_hs0_csis2_rx_byte");

	fimc_is_set_rate(pdev, "dout_clkdiv_pclk_cam1_sclvra_246", 246 * 1000000);
	fimc_is_set_rate(pdev, "dout_clkdiv_pclk_cam1_arm_167", 167 * 1000000);
	fimc_is_set_rate(pdev, "dout_clkdiv_pclk_cam1_busperi_167", 167 * 1000000);
	fimc_is_set_rate(pdev, "dout_clkdiv_pclk_cam1_busperi_84", 84 * 1000000);

	/* ISP0 */
	fimc_is_enable(pdev, "mout_user_mux_aclk_isp0_isp0_590");
	fimc_is_enable(pdev, "mout_user_mux_aclk_isp0_tpu_590");
	fimc_is_enable(pdev, "mout_user_mux_aclk_isp0_trex_532");

	fimc_is_set_rate(pdev, "dout_clkdiv_pclk_isp0_isp0_295", 276 * 1000000);
	fimc_is_set_rate(pdev, "dout_clkdiv_pclk_isp0_tpu_295", 276 * 1000000);
	fimc_is_set_rate(pdev, "dout_clkdiv_pclk_isp0_trex_266", 266 * 1000000);
	fimc_is_set_rate(pdev, "dout_clkdiv_pclk_isp0_trex_133", 133 * 1000000);

	/* ISP1 */
	fimc_is_enable(pdev, "mout_user_mux_aclk_isp1_isp1_468");
	fimc_is_enable(pdev, "mout_user_mux_aclk_isp1_ahb_117");

	fimc_is_set_rate(pdev, "dout_clkdiv_pclk_isp1_isp1_234", 234 * 1000000);

	/* RCG(Root Clock Gating) */
	/* BLK_CAM0 */
	writel(0x1, EXYNOS7420_VA_SYSREG + 0x0518);
	writel(0x2, EXYNOS7420_VA_SYSREG + 0x051c);
	writel(0xf00, EXYNOS7420_VA_SYSREG + 0x0524);
	writel(0x1, EXYNOS7420_VA_SYSREG + 0x0540);
	writel(0x1ff, EXYNOS7420_VA_SYSREG + 0x0544);

	/* BLK_CAM1 */
	writel(0x1, EXYNOS7420_VA_SYSREG + 0x0618);
	writel(0x10fd, EXYNOS7420_VA_SYSREG + 0x0624);
	writel(0x1, EXYNOS7420_VA_SYSREG + 0x064c);
	writel(0x1ff, EXYNOS7420_VA_SYSREG + 0x0650);

	/* BLK_ISP0 */
	writel(0x1, EXYNOS7420_VA_SYSREG + 0x151c);
	writel(0x1, EXYNOS7420_VA_SYSREG + 0x1524);
	writel(0x1f, EXYNOS7420_VA_SYSREG + 0x1538);
	writel(0x1, EXYNOS7420_VA_SYSREG + 0x153c);

	/* BLK_ISP1 */
	writel(0x3, EXYNOS7420_VA_SYSREG + 0x1724);

	/* for debugging */
#if 0
	writel(0x55233000, EXYNOS7420_MUX_SEL_TOP04);
	writel(0x66666000, EXYNOS7420_MUX_SEL_TOP05);
	writel(0x63220000, EXYNOS7420_MUX_SEL_TOP06);
	writel(0x31122200, EXYNOS7420_MUX_SEL_TOP07);
	writel(0x11111000, EXYNOS7420_MUX_ENABLE_TOP04);
	writel(0x11111000, EXYNOS7420_MUX_ENABLE_TOP05);
	writel(0x11110000, EXYNOS7420_MUX_ENABLE_TOP06);
	writel(0x11111100, EXYNOS7420_MUX_ENABLE_TOP07);
	writel(0x00114000, EXYNOS7420_DIV_TOP04);
	writel(0x00003000, EXYNOS7420_DIV_TOP05);
	writel(0x00030000, EXYNOS7420_DIV_TOP06);
	writel(0x10133100, EXYNOS7420_DIV_TOP07);

	writel(0x00000001, EXYNOS7420_MUX_SEL_BUS0);
	writel(0x0000019F, EXYNOS7420_ENABLE_ACLK_BUS0);
	writel(0x00003E00, EXYNOS7420_ENABLE_PCLK_BUS0);

	writel(0x11111111, EXYNOS7420_MUX_SEL_CAM00);
	writel(0x00000001, EXYNOS7420_MUX_SEL_CAM01);
	writel(0x00011111, EXYNOS7420_MUX_SEL_CAM02);
	writel(0x11111111, EXYNOS7420_MUX_ENABLE_CAM00);
	writel(0x00000001, EXYNOS7420_MUX_ENABLE_CAM01);
	writel(0x00011111, EXYNOS7420_MUX_ENABLE_CAM02);
	writel(0x01111111, EXYNOS7420_DIV_CAM0);
	writel(0x03F31F1F, EXYNOS7420_ENABLE_IP_CAM00);
	writel(0xD1FF1F01, EXYNOS7420_ENABLE_IP_CAM01);
	writel(0x000000F1, EXYNOS7420_ENABLE_IP_CAM02);

	writel(0x00111111, EXYNOS7420_MUX_SEL_CAM10);
	writel(0x10000111, EXYNOS7420_MUX_SEL_CAM11);
	writel(0x00111111, EXYNOS7420_MUX_ENABLE_CAM10);
	writel(0x10110111, EXYNOS7420_MUX_ENABLE_CAM11);
	writel(0x00000313, EXYNOS7420_DIV_CAM1);
	writel(0x337F3FFF, EXYNOS7420_ENABLE_IP_CAM10);
	writel(0x17F7FF1F, EXYNOS7420_ENABLE_IP_CAM11);
	writel(0x0100FF72, EXYNOS7420_ENABLE_IP_CAM12);

	writel(0x00000111, EXYNOS7420_MUX_SEL_ISP0);
	writel(0x00000111, EXYNOS7420_MUX_ENABLE_ISP0);
	writel(0x00003111, EXYNOS7420_DIV_ISP0);
	writel(0xFFFFFFFF, EXYNOS7420_ENABLE_IP_ISP0);

	writel(0x00000011, EXYNOS7420_MUX_SEL_ISP1);
	writel(0x00000011, EXYNOS7420_MUX_ENABLE_ISP1);
	writel(0x00000001, EXYNOS7420_DIV_ISP1);
	writel(0x00011F11, EXYNOS7420_ENABLE_IP_ISP1);
#endif
#if 0
	printk(KERN_DEBUG "TOP0\n");
	PRINT_CLK(EXYNOS7420_MUX_SEL_TOP04, "MUX4");
	PRINT_CLK(EXYNOS7420_MUX_SEL_TOP05, "MUX5");
	PRINT_CLK(EXYNOS7420_MUX_SEL_TOP06, "MUX6");
	PRINT_CLK(EXYNOS7420_MUX_SEL_TOP07, "MUX7");
	PRINT_CLK(EXYNOS7420_MUX_ENABLE_TOP04, "MXE4");
	PRINT_CLK(EXYNOS7420_MUX_ENABLE_TOP05, "MXE5");
	PRINT_CLK(EXYNOS7420_MUX_ENABLE_TOP06, "MXE6");
	PRINT_CLK(EXYNOS7420_MUX_ENABLE_TOP07, "MXE7");
	PRINT_CLK(EXYNOS7420_DIV_TOP04, "DIV4");
	PRINT_CLK(EXYNOS7420_DIV_TOP05, "DIV5");
	PRINT_CLK(EXYNOS7420_DIV_TOP06, "DIV6");
	PRINT_CLK(EXYNOS7420_DIV_TOP07, "DIV7");
	PRINT_CLK(EXYNOS7420_ENABLE_ACLK_TOP04, "ENA4");
	PRINT_CLK(EXYNOS7420_ENABLE_ACLK_TOP05, "ENA5");
	PRINT_CLK(EXYNOS7420_ENABLE_ACLK_TOP06, "ENA6");
	PRINT_CLK(EXYNOS7420_ENABLE_ACLK_TOP07, "ENA7");

	printk(KERN_DEBUG "BUS0\n");
	PRINT_CLK(EXYNOS7420_MUX_SEL_BUS0, "MUX0");
	PRINT_CLK(EXYNOS7420_ENABLE_ACLK_BUS0, "ENAA");
	PRINT_CLK(EXYNOS7420_ENABLE_PCLK_BUS0, "ENAP");

	printk(KERN_DEBUG "CAM0\n");
	PRINT_CLK(EXYNOS7420_MUX_SEL_CAM00, "MUX0");
	PRINT_CLK(EXYNOS7420_MUX_SEL_CAM01, "MUX1");
	PRINT_CLK(EXYNOS7420_MUX_SEL_CAM02, "MUX2");
	PRINT_CLK(EXYNOS7420_MUX_ENABLE_CAM00, "MXE0");
	PRINT_CLK(EXYNOS7420_MUX_ENABLE_CAM01, "MXE1");
	PRINT_CLK(EXYNOS7420_MUX_ENABLE_CAM02, "MXE2");
	/* PRINT_CLK(EXYNOS7420_MUX_IGNORE_CAM0); */
	PRINT_CLK(EXYNOS7420_DIV_CAM0, "DIV0");
	PRINT_CLK(EXYNOS7420_ENABLE_IP_CAM00, "ENA0");
	PRINT_CLK(EXYNOS7420_ENABLE_IP_CAM01, "ENA1");
	PRINT_CLK(EXYNOS7420_ENABLE_IP_CAM02, "ENA2");

	printk(KERN_DEBUG "CAM1\n");
	PRINT_CLK(EXYNOS7420_MUX_SEL_CAM10, "MUX0");
	PRINT_CLK(EXYNOS7420_MUX_SEL_CAM11, "MUX1");
	PRINT_CLK(EXYNOS7420_MUX_ENABLE_CAM10, "MXE0");
	PRINT_CLK(EXYNOS7420_MUX_ENABLE_CAM11, "MXE1");
	/* PRINT_CLK(EXYNOS7420_MUX_IGNORE_CAM1); */
	PRINT_CLK(EXYNOS7420_DIV_CAM1, "DIV0");
	PRINT_CLK(EXYNOS7420_ENABLE_IP_CAM10, "ENA0");
	PRINT_CLK(EXYNOS7420_ENABLE_IP_CAM11, "ENA1");
	PRINT_CLK(EXYNOS7420_ENABLE_IP_CAM12, "ENA2");

	printk(KERN_DEBUG "ISP0\n");
	PRINT_CLK(EXYNOS7420_MUX_SEL_ISP0, "MUX0");
	PRINT_CLK(EXYNOS7420_MUX_ENABLE_ISP0, "MXE0");
	PRINT_CLK(EXYNOS7420_DIV_ISP0, "DIV0");
	PRINT_CLK(EXYNOS7420_ENABLE_IP_ISP0, "ENA0");

	printk(KERN_DEBUG "ISP1\n");
	PRINT_CLK(EXYNOS7420_MUX_SEL_ISP1, "MUX0");
	PRINT_CLK(EXYNOS7420_MUX_ENABLE_ISP1, "MXE0");
	PRINT_CLK(EXYNOS7420_DIV_ISP1, "DIV0");
	PRINT_CLK(EXYNOS7420_ENABLE_IP_ISP1, "ENA0");
#endif

	pdata->clock_on = true;

p_err:
	return 0;
}

int exynos7420_fimc_is_clk_off(struct platform_device *pdev)
{
	int ret = 0;
	struct exynos_platform_fimc_is *pdata;

	pdata = dev_get_platdata(&pdev->dev);
	if (!pdata->clock_on) {
		pr_err("clk_off is fail(already off)\n");
		ret = -EINVAL;
		goto p_err;
	}

	/* BUS0 */
	fimc_is_disable(pdev, "gate_aclk_lh_cam0");
	fimc_is_disable(pdev, "gate_aclk_lh_cam1");
	fimc_is_disable(pdev, "gate_aclk_lh_isp");
	fimc_is_disable(pdev, "gate_aclk_noc_bus0_nrt");

	/* CAM0 */
	fimc_is_disable(pdev, "mout_user_mux_aclk_cam0_csis0_690");
	fimc_is_disable(pdev, "mout_user_mux_aclk_cam0_bnsa_690");
	fimc_is_disable(pdev, "mout_user_mux_aclk_cam0_bnsb_690");
	fimc_is_disable(pdev, "mout_user_mux_aclk_cam0_bnsd_690");
	fimc_is_disable(pdev, "mout_user_mux_aclk_cam0_csis1_174");
	fimc_is_disable(pdev, "mout_user_mux_aclk_cam0_3aa0_690");
	fimc_is_disable(pdev, "mout_user_mux_aclk_cam0_3aa1_468");
	fimc_is_disable(pdev, "mout_user_mux_aclk_cam0_trex_532");
	fimc_is_disable(pdev, "mout_user_mux_aclk_cam0_nocp_133");
	fimc_is_disable(pdev, "mout_user_mux_phyclk_rxbyteclkhs0_s2a");
	fimc_is_disable(pdev, "mout_user_mux_phyclk_rxbyteclkhs0_s4");
	fimc_is_disable(pdev, "mout_user_mux_phyclk_rxbyteclkhs1_s4");
	fimc_is_disable(pdev, "mout_user_mux_phyclk_rxbyteclkhs2_s4");
	fimc_is_disable(pdev, "mout_user_mux_phyclk_rxbyteclkhs3_s4");

	/* CAM1 */
	fimc_is_disable(pdev, "mout_user_mux_aclk_cam1_sclvra_491");
	fimc_is_disable(pdev, "mout_user_mux_aclk_cam1_arm_668");
	fimc_is_disable(pdev, "mout_user_mux_aclk_cam1_busperi_334");
	fimc_is_disable(pdev, "mout_user_mux_aclk_cam1_bnscsis_133");
	fimc_is_disable(pdev, "mout_user_mux_aclk_cam1_nocp_133");
	fimc_is_disable(pdev, "mout_user_mux_aclk_cam1_trex_532");
	fimc_is_disable(pdev, "mout_user_mux_sclk_isp_spi0");
	fimc_is_disable(pdev, "mout_user_mux_sclk_isp_spi1");
	fimc_is_disable(pdev, "mout_user_mux_sclk_isp_uart");
	fimc_is_disable(pdev, "mout_user_mux_phyclk_hs0_csis2_rx_byte");

	/* ISP0 */
	fimc_is_disable(pdev, "mout_user_mux_aclk_isp0_isp0_590");
	fimc_is_disable(pdev, "mout_user_mux_aclk_isp0_tpu_590");
	fimc_is_disable(pdev, "mout_user_mux_aclk_isp0_trex_532");

	/* ISP1 */
	fimc_is_disable(pdev, "mout_user_mux_aclk_isp1_isp1_468");
	fimc_is_disable(pdev, "mout_user_mux_aclk_isp1_ahb_117");

	pdata->clock_on = false;

p_err:
	return ret;
}

int exynos7420_fimc_is_print_clk(struct platform_device *pdev)
{
	pr_debug("%s\n", __func__);

	/* INPUT CLOCK */
	fimc_is_get_rate(pdev, "isp_pll");
	fimc_is_get_rate(pdev, "cam_pll");

	printk(KERN_DEBUG "#################### CAM0 clock ####################\n");
	/* CAM0 */
	/* CSIS0 */
	fimc_is_get_rate(pdev, "dout_aclk_cam0_csis0_690");
	/* BNS A */
	fimc_is_get_rate(pdev, "dout_aclk_cam0_bnsa_690");
	fimc_is_get_rate(pdev, "dout_clkdiv_pclk_cam0_bnsa_345");
	/* BNS B */
	fimc_is_get_rate(pdev, "dout_aclk_cam0_bnsb_690");
	fimc_is_get_rate(pdev, "dout_clkdiv_pclk_cam0_bnsb_345");
	/* BNS D */
	fimc_is_get_rate(pdev, "dout_aclk_cam0_bnsd_690");
	fimc_is_get_rate(pdev, "dout_clkdiv_pclk_cam0_bnsd_345");
	/* CSIS1 */
	fimc_is_get_rate(pdev, "dout_aclk_cam0_csis1_174");
	/* 3AA0 */
	fimc_is_get_rate(pdev, "dout_aclk_cam0_3aa0_690");
	fimc_is_get_rate(pdev, "dout_clkdiv_pclk_cam0_3aa0_345");
	/* 3AA1 */
	fimc_is_get_rate(pdev, "dout_aclk_cam0_3aa1_468");
	fimc_is_get_rate(pdev, "dout_clkdiv_pclk_cam0_3aa1_234");
	/* TREX */
	fimc_is_get_rate(pdev, "dout_aclk_cam0_trex_532");
	fimc_is_get_rate(pdev, "dout_clkdiv_pclk_cam0_trex_266");
	fimc_is_get_rate(pdev, "dout_clkdiv_pclk_cam0_trex_133");
	/* NOCP */
	fimc_is_get_rate(pdev, "dout_aclk_cam0_nocp_133");
	/* PHY .. */
	fimc_is_get_rate(pdev, "phyclk_rxbyteclkhs0_s2a");
	fimc_is_get_rate(pdev, "phyclk_rxbyteclkhs0_s4");
	fimc_is_get_rate(pdev, "phyclk_rxbyteclkhs1_s4");
	fimc_is_get_rate(pdev, "phyclk_rxbyteclkhs2_s4");
	fimc_is_get_rate(pdev, "phyclk_rxbyteclkhs3_s4");

	printk(KERN_DEBUG "#################### CAM1 clock ####################\n");
	/* CAM1 */
	/* VRA */
	fimc_is_get_rate(pdev, "dout_aclk_cam1_sclvra_491");
	fimc_is_get_rate(pdev, "dout_clkdiv_pclk_cam1_sclvra_246");
	/* CORTEX */
	fimc_is_get_rate(pdev, "dout_aclk_cam1_arm_668");
	fimc_is_get_rate(pdev, "dout_clkdiv_pclk_cam1_arm_167");
	/* BUSPERI */
	fimc_is_get_rate(pdev, "dout_aclk_cam1_busperi_334");
	fimc_is_get_rate(pdev, "dout_clkdiv_pclk_cam1_busperi_167");
	fimc_is_get_rate(pdev, "dout_clkdiv_pclk_cam1_busperi_84");
	/* BNS C */
	fimc_is_get_rate(pdev, "dout_aclk_cam1_bnscsis_133");
	/* PHY .. */
	fimc_is_get_rate(pdev, "dout_aclk_cam1_nocp_133");
	fimc_is_get_rate(pdev, "dout_aclk_cam1_trex_532");
	/* sclk */
	fimc_is_get_rate(pdev, "dout_sclk_isp_spi0");
	fimc_is_get_rate(pdev, "dout_sclk_isp_spi1");
	fimc_is_get_rate(pdev, "dout_sclk_isp_uart");

	printk(KERN_DEBUG "#################### ISP0 clock ####################\n");
	/* ISP0 */
	/* ISP */
	fimc_is_get_rate(pdev, "dout_aclk_isp0_isp0_590");
	fimc_is_get_rate(pdev, "dout_clkdiv_pclk_isp0_isp0_295");
	/* TPU */
	fimc_is_get_rate(pdev, "dout_aclk_isp0_tpu_590");
	fimc_is_get_rate(pdev, "dout_clkdiv_pclk_isp0_tpu_295");
	/* TREX */
	fimc_is_get_rate(pdev, "dout_aclk_isp0_trex_532");
	fimc_is_get_rate(pdev, "dout_clkdiv_pclk_isp0_trex_266");
	fimc_is_get_rate(pdev, "dout_clkdiv_pclk_isp0_trex_133");

	printk(KERN_DEBUG "#################### ISP1 clock ####################\n");
	/* ISP1 */
	/* ISP */
	fimc_is_get_rate(pdev, "dout_aclk_isp1_isp1_468");
	fimc_is_get_rate(pdev, "dout_clkdiv_pclk_isp1_isp1_234");
	/* ETC */
	fimc_is_get_rate(pdev, "dout_aclk_isp1_ahb_117");

	return 0;
}
#endif

/* Wrapper functions */
int exynos_fimc_is_cfg_clk(struct platform_device *pdev)
{
#if defined(CONFIG_SOC_EXYNOS7420)
	exynos7420_fimc_is_cfg_clk(pdev);
#endif
	return 0;
}

int exynos_fimc_is_clk_on(struct platform_device *pdev)
{
#if defined(CONFIG_SOC_EXYNOS7420)
	exynos7420_fimc_is_clk_on(pdev);
#endif
	return 0;
}

int exynos_fimc_is_clk_off(struct platform_device *pdev)
{
#if defined(CONFIG_SOC_EXYNOS7420)
	exynos7420_fimc_is_clk_off(pdev);
#endif
	return 0;
}

int exynos_fimc_is_print_clk(struct platform_device *pdev)
{
#if defined(CONFIG_SOC_EXYNOS7420)
	exynos7420_fimc_is_print_clk(pdev);
#endif
	return 0;
}

int exynos_fimc_is_set_user_clk_gate(u32 group_id, bool is_on,
	u32 user_scenario_id,
	unsigned long msk_state,
	struct exynos_fimc_is_clk_gate_info *gate_info)
{
	return 0;
}

int exynos_fimc_is_clk_gate(u32 clk_gate_id, bool is_on)
{
#if defined(CONFIG_SOC_EXYNOS7420)
	exynos7420_fimc_is_clk_gate(clk_gate_id, is_on);
#endif
	return 0;
}

