/* linux/arch/arm/mach-exynos/setup-fimc-sensor.c
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
#ifdef CONFIG_OF
#include <linux/of_gpio.h>
#endif
#if defined(CONFIG_SOC_EXYNOS7420)
#include <mach/regs-clock-exynos7420.h>
#endif

#include <exynos-fimc-is.h>
#include <exynos-fimc-is-sensor.h>
#include <exynos-fimc-is-module.h>

char *clk_g_list[CLK_NUM] = {
	"cam_pll",
	"isp_pll",
	"dout_aclk_cam0_3aa0_690",
	"dout_aclk_cam0_3aa1_468",
	"dout_aclk_cam0_bnsa_690",
	"dout_aclk_cam0_bnsb_690",
	"dout_aclk_cam0_bnsd_690",
	"dout_aclk_cam0_csis0_690",
	"dout_aclk_cam0_csis1_174",
	"dout_aclk_cam0_nocp_133",
	"dout_aclk_cam0_trex_532",
	"dout_aclk_cam1_arm_668",
	"dout_aclk_cam1_bnscsis_133",
	"dout_aclk_cam1_busperi_334",
	"dout_aclk_cam1_nocp_133",
	"dout_aclk_cam1_sclvra_491",
	"dout_aclk_cam1_trex_532",
	"dout_aclk_isp0_isp0_590",
	"dout_aclk_isp0_tpu_590",
	"dout_aclk_isp0_trex_532",
	"dout_aclk_isp1_ahb_117",
	"dout_aclk_isp1_isp1_468",
	"dout_clkdiv_pclk_cam0_3aa0_345",
	"dout_clkdiv_pclk_cam0_3aa1_234",
	"dout_clkdiv_pclk_cam0_bnsa_345",
	"dout_clkdiv_pclk_cam0_bnsb_345",
	"dout_clkdiv_pclk_cam0_bnsd_345",
	"dout_clkdiv_pclk_cam0_trex_133",
	"dout_clkdiv_pclk_cam0_trex_266",
	"dout_clkdiv_pclk_cam1_arm_167",
	"dout_clkdiv_pclk_cam1_busperi_167",
	"dout_clkdiv_pclk_cam1_busperi_84",
	"dout_clkdiv_pclk_cam1_sclvra_246",
	"dout_clkdiv_pclk_isp0_isp0_295",
	"dout_clkdiv_pclk_isp0_tpu_295",
	"dout_clkdiv_pclk_isp0_trex_133",
	"dout_clkdiv_pclk_isp0_trex_266",
	"dout_clkdiv_pclk_isp1_isp1_234",
	"dout_sclk_isp_spi0",
	"dout_sclk_isp_spi1",
	"dout_sclk_isp_uart",
	"gate_aclk_csis0_i_wrap",
	"gate_aclk_csis1_i_wrap",
	"gate_aclk_csis3_i_wrap",
	"gate_aclk_fimc_bns_a",
	"gate_aclk_fimc_bns_b",
	"gate_aclk_fimc_bns_c",
	"gate_aclk_fimc_bns_d",
	"gate_aclk_lh_cam0",
	"gate_aclk_lh_cam1",
	"gate_aclk_lh_isp",
	"gate_aclk_noc_bus0_nrt",
	"gate_aclk_wrap_csis2",
	"gate_cclk_asyncapb_socp_fimc_bns_a",
	"gate_cclk_asyncapb_socp_fimc_bns_b",
	"gate_cclk_asyncapb_socp_fimc_bns_c",
	"gate_cclk_asyncapb_socp_fimc_bns_d",
	"gate_pclk_asyncapb_socp_fimc_bns_a",
	"gate_pclk_asyncapb_socp_fimc_bns_b",
	"gate_pclk_asyncapb_socp_fimc_bns_c",
	"gate_pclk_asyncapb_socp_fimc_bns_d",
	"gate_pclk_csis0",
	"gate_pclk_csis1",
	"gate_pclk_csis2",
	"gate_pclk_csis3",
	"gate_pclk_fimc_bns_a",
	"gate_pclk_fimc_bns_b",
	"gate_pclk_fimc_bns_c",
	"gate_pclk_fimc_bns_d",
	"mout_user_mux_aclk_cam0_3aa0_690",
	"mout_user_mux_aclk_cam0_3aa1_468",
	"mout_user_mux_aclk_cam0_bnsa_690",
	"mout_user_mux_aclk_cam0_bnsb_690",
	"mout_user_mux_aclk_cam0_bnsd_690",
	"mout_user_mux_aclk_cam0_csis0_690",
	"mout_user_mux_aclk_cam0_csis1_174",
	"mout_user_mux_aclk_cam0_nocp_133",
	"mout_user_mux_aclk_cam0_trex_532",
	"mout_user_mux_aclk_cam1_arm_668",
	"mout_user_mux_aclk_cam1_bnscsis_133",
	"mout_user_mux_aclk_cam1_busperi_334",
	"mout_user_mux_aclk_cam1_nocp_133",
	"mout_user_mux_aclk_cam1_sclvra_491",
	"mout_user_mux_aclk_cam1_trex_532",
	"mout_user_mux_aclk_isp0_isp0_590",
	"mout_user_mux_aclk_isp0_tpu_590",
	"mout_user_mux_aclk_isp0_trex_532",
	"mout_user_mux_aclk_isp1_ahb_117",
	"mout_user_mux_aclk_isp1_isp1_468",
	"mout_user_mux_phyclk_hs0_csis2_rx_byte",
	"mout_user_mux_phyclk_rxbyteclkhs0_s2a",
	"mout_user_mux_phyclk_rxbyteclkhs0_s4",
	"mout_user_mux_phyclk_rxbyteclkhs1_s4",
	"mout_user_mux_phyclk_rxbyteclkhs2_s4",
	"mout_user_mux_phyclk_rxbyteclkhs3_s4",
	"mout_user_mux_sclk_isp_spi0",
	"mout_user_mux_sclk_isp_spi1",
	"mout_user_mux_sclk_isp_uart",
	"phyclk_hs0_csis2_rx_byte",
	"phyclk_rxbyteclkhs0_s2a",
	"phyclk_rxbyteclkhs0_s4",
	"phyclk_rxbyteclkhs1_s4",
	"phyclk_rxbyteclkhs2_s4",
	"phyclk_rxbyteclkhs3_s4",
};

struct clk *clk_target_list[CLK_NUM];

#if defined(CONFIG_SOC_EXYNOS7420)
static int exynos7420_fimc_is_csi0_gate(struct platform_device *pdev, bool mask)
{
	int ret = 0;

	if (mask) {
		fimc_is_disable(pdev, "gate_pclk_csis0");
		fimc_is_disable(pdev, "gate_aclk_csis0_i_wrap");
		fimc_is_disable(pdev, "phyclk_rxbyteclkhs0_s4");
		fimc_is_disable(pdev, "phyclk_rxbyteclkhs1_s4");
		fimc_is_disable(pdev, "phyclk_rxbyteclkhs2_s4");
		fimc_is_disable(pdev, "phyclk_rxbyteclkhs3_s4");
	} else {
		fimc_is_enable(pdev, "gate_pclk_csis0");
		fimc_is_enable(pdev, "gate_aclk_csis0_i_wrap");
		fimc_is_enable(pdev, "phyclk_rxbyteclkhs0_s4");
		fimc_is_enable(pdev, "phyclk_rxbyteclkhs1_s4");
		fimc_is_enable(pdev, "phyclk_rxbyteclkhs2_s4");
		fimc_is_enable(pdev, "phyclk_rxbyteclkhs3_s4");
	}

	return ret;
}

static int exynos7420_fimc_is_csi1_gate(struct platform_device *pdev, bool mask)
{
	int ret = 0;

	if (mask) {
		fimc_is_disable(pdev, "gate_pclk_csis1");
		fimc_is_disable(pdev, "gate_aclk_csis1_i_wrap");
		fimc_is_disable(pdev, "phyclk_rxbyteclkhs0_s2a");
	} else {
		fimc_is_enable(pdev, "gate_pclk_csis1");
		fimc_is_enable(pdev, "gate_aclk_csis1_i_wrap");
		fimc_is_enable(pdev, "phyclk_rxbyteclkhs0_s2a");
	}

	return ret;
}

static int exynos7420_fimc_is_csi2_gate(struct platform_device *pdev, bool mask)
{
	int ret = 0;

	if (mask) {
		fimc_is_disable(pdev, "gate_pclk_csis2");
		fimc_is_disable(pdev, "gate_aclk_wrap_csis2");
		fimc_is_disable(pdev, "phyclk_hs0_csis2_rx_byte");
	} else {
		fimc_is_enable(pdev, "gate_pclk_csis2");
		fimc_is_enable(pdev, "gate_aclk_wrap_csis2");
		fimc_is_enable(pdev, "phyclk_hs0_csis2_rx_byte");
	}

	return ret;
}

static int exynos7420_fimc_is_csi3_gate(struct platform_device *pdev, bool mask)
{
	int ret = 0;

	if (mask) {
		fimc_is_disable(pdev, "gate_pclk_csis3");
		fimc_is_disable(pdev, "gate_aclk_csis3_i_wrap");
	} else {
		fimc_is_enable(pdev, "gate_pclk_csis3");
		fimc_is_enable(pdev, "gate_aclk_csis3_i_wrap");
	}

	return ret;
}

static int exynos7420_fimc_is_bns0_gate(struct platform_device *pdev, bool mask)
{
	int ret = 0;

	if (mask) {
		fimc_is_disable(pdev, "gate_pclk_asyncapb_socp_fimc_bns_a");
		fimc_is_disable(pdev, "gate_cclk_asyncapb_socp_fimc_bns_a");
		fimc_is_disable(pdev, "gate_pclk_fimc_bns_a");
		fimc_is_disable(pdev, "gate_aclk_fimc_bns_a");
	} else {
		fimc_is_enable(pdev, "gate_pclk_asyncapb_socp_fimc_bns_a");
		fimc_is_enable(pdev, "gate_cclk_asyncapb_socp_fimc_bns_a");
		fimc_is_enable(pdev, "gate_pclk_fimc_bns_a");
		fimc_is_enable(pdev, "gate_aclk_fimc_bns_a");
	}

	return ret;
}

static int exynos7420_fimc_is_bns1_gate(struct platform_device *pdev, bool mask)
{
	int ret = 0;

	if (mask) {
		fimc_is_disable(pdev, "gate_pclk_asyncapb_socp_fimc_bns_b");
		fimc_is_disable(pdev, "gate_cclk_asyncapb_socp_fimc_bns_b");
		fimc_is_disable(pdev, "gate_pclk_fimc_bns_b");
		fimc_is_disable(pdev, "gate_aclk_fimc_bns_b");
	} else {
		fimc_is_enable(pdev, "gate_pclk_asyncapb_socp_fimc_bns_b");
		fimc_is_enable(pdev, "gate_cclk_asyncapb_socp_fimc_bns_b");
		fimc_is_enable(pdev, "gate_pclk_fimc_bns_b");
		fimc_is_enable(pdev, "gate_aclk_fimc_bns_b");
	}

	return ret;
}

static int exynos7420_fimc_is_bns2_gate(struct platform_device *pdev, bool mask)
{
	int ret = 0;

	if (mask) {
		fimc_is_disable(pdev, "gate_pclk_asyncapb_socp_fimc_bns_c");
		fimc_is_disable(pdev, "gate_cclk_asyncapb_socp_fimc_bns_c");
		fimc_is_disable(pdev, "gate_pclk_fimc_bns_c");
		fimc_is_disable(pdev, "gate_aclk_fimc_bns_c");
	} else {
		fimc_is_enable(pdev, "gate_pclk_asyncapb_socp_fimc_bns_c");
		fimc_is_enable(pdev, "gate_cclk_asyncapb_socp_fimc_bns_c");
		fimc_is_enable(pdev, "gate_pclk_fimc_bns_c");
		fimc_is_enable(pdev, "gate_aclk_fimc_bns_c");
	}

	return ret;
}

static int exynos7420_fimc_is_bns3_gate(struct platform_device *pdev, bool mask)
{
	int ret = 0;

	if (mask) {
		fimc_is_disable(pdev, "gate_pclk_asyncapb_socp_fimc_bns_d");
		fimc_is_disable(pdev, "gate_cclk_asyncapb_socp_fimc_bns_d");
		fimc_is_disable(pdev, "gate_pclk_fimc_bns_d");
		fimc_is_disable(pdev, "gate_aclk_fimc_bns_d");
	} else {
		fimc_is_enable(pdev, "gate_pclk_asyncapb_socp_fimc_bns_d");
		fimc_is_enable(pdev, "gate_cclk_asyncapb_socp_fimc_bns_d");
		fimc_is_enable(pdev, "gate_pclk_fimc_bns_d");
		fimc_is_enable(pdev, "gate_aclk_fimc_bns_d");
	}

	return ret;
}

int exynos7420_fimc_is_sensor_iclk_get(struct platform_device *pdev,
	u32 scenario,
	u32 channel)
{
	char *conid;
	static int cnt = 0;
	int id = 0;
	struct clk *target;

	if (cnt >= 1)
		return 0;

	for (id = 0; id < CLK_NUM; id++) {
		conid = clk_g_list[id];
		target = clk_get(&pdev->dev, conid);

		if (IS_ERR_OR_NULL(target)) {
			pr_err("%s: could not lookup clock : %s\n", __func__, conid);
			return -EINVAL;
		}
		clk_target_list[id] = target;
	}
	cnt++;

	return 0;
}

int exynos7420_fimc_is_sensor_iclk_cfg(struct platform_device *pdev,
	u32 scenario,
	u32 channel)
{
	/* this dummy enable make refcount to be 1 for clock off */
	exynos7420_fimc_is_csi0_gate(pdev, false);
	exynos7420_fimc_is_csi1_gate(pdev, false);
	exynos7420_fimc_is_csi2_gate(pdev, false);
	exynos7420_fimc_is_csi3_gate(pdev, false);

	exynos7420_fimc_is_bns0_gate(pdev, false);
	exynos7420_fimc_is_bns1_gate(pdev, false);
	exynos7420_fimc_is_bns2_gate(pdev, false);
	exynos7420_fimc_is_bns3_gate(pdev, false);

	return 0;
}

int exynos7420_fimc_is_sensor_iclk_on(struct platform_device *pdev,
	u32 scenario,
	u32 channel)
{
	int ret = 0;

	switch (channel) {
	case 0:
		/* CSI */
		exynos7420_fimc_is_csi1_gate(pdev, true);
		exynos7420_fimc_is_csi2_gate(pdev, true);
		exynos7420_fimc_is_csi3_gate(pdev, true);
		/* BNS */
		exynos7420_fimc_is_bns1_gate(pdev, true);
		exynos7420_fimc_is_bns2_gate(pdev, true);
		break;
	case 1:
		/* CSI */
		exynos7420_fimc_is_csi0_gate(pdev, true);
		exynos7420_fimc_is_csi2_gate(pdev, true);
		exynos7420_fimc_is_csi3_gate(pdev, true);
		/* BNS */
		exynos7420_fimc_is_bns0_gate(pdev, true);
		exynos7420_fimc_is_bns2_gate(pdev, true);
		exynos7420_fimc_is_bns3_gate(pdev, true);
		break;
	case 2:
		/* CSI */
		exynos7420_fimc_is_csi0_gate(pdev, true);
		exynos7420_fimc_is_csi1_gate(pdev, true);
		exynos7420_fimc_is_csi3_gate(pdev, true);
		/* BNS */
		exynos7420_fimc_is_bns0_gate(pdev, true);
		exynos7420_fimc_is_bns1_gate(pdev, true);
		exynos7420_fimc_is_bns3_gate(pdev, true);
		break;
	default:
		pr_err("channel is invalid(%d)\n", channel);
		ret = -EINVAL;
		goto p_err;
		break;
	}

	if (scenario == SENSOR_SCENARIO_NORMAL)
		goto p_err;

	switch (channel) {
	case 0:
		/* BUS0 */
		fimc_is_enable(pdev, "gate_aclk_lh_cam0");

		/* CAM0 */
		fimc_is_enable(pdev, "mout_user_mux_aclk_cam0_csis0_690");
		fimc_is_enable(pdev, "mout_user_mux_aclk_cam0_bnsa_690");
		fimc_is_enable(pdev, "mout_user_mux_aclk_cam0_bnsd_690");
		fimc_is_enable(pdev, "mout_user_mux_aclk_cam0_trex_532");
		fimc_is_enable(pdev, "mout_user_mux_aclk_cam0_nocp_133");
		fimc_is_enable(pdev, "mout_user_mux_phyclk_rxbyteclkhs0_s4");
		fimc_is_enable(pdev, "mout_user_mux_phyclk_rxbyteclkhs1_s4");
		fimc_is_enable(pdev, "mout_user_mux_phyclk_rxbyteclkhs2_s4");
		fimc_is_enable(pdev, "mout_user_mux_phyclk_rxbyteclkhs3_s4");

		fimc_is_set_rate(pdev, "dout_clkdiv_pclk_cam0_bnsa_345", 330 * 1000000);
		fimc_is_set_rate(pdev, "dout_clkdiv_pclk_cam0_bnsd_345", 330 * 1000000);
		fimc_is_set_rate(pdev, "dout_clkdiv_pclk_cam0_trex_266", 266 * 1000000);
		fimc_is_set_rate(pdev, "dout_clkdiv_pclk_cam0_trex_133", 133 * 1000000);
		break;
	case 1:
		/* BUS0 */
		fimc_is_enable(pdev, "gate_aclk_lh_cam0");

		/* CAM0 */
		fimc_is_enable(pdev, "mout_user_mux_aclk_cam0_csis1_174");
		fimc_is_enable(pdev, "mout_user_mux_aclk_cam0_bnsb_690");
		fimc_is_enable(pdev, "mout_user_mux_aclk_cam0_trex_532");
		fimc_is_enable(pdev, "mout_user_mux_aclk_cam0_nocp_133");
		fimc_is_enable(pdev, "mout_user_mux_phyclk_rxbyteclkhs0_s2a");

		fimc_is_set_rate(pdev, "dout_clkdiv_pclk_cam0_bnsb_345", 330 * 1000000);
		break;
	case 2:
		/* BUS0 */
		fimc_is_enable(pdev, "gate_aclk_lh_cam1");

		/* CAM1 */
		fimc_is_enable(pdev, "mout_user_mux_aclk_cam1_bnscsis_133");
		fimc_is_enable(pdev, "mout_user_mux_aclk_cam1_trex_532");
		fimc_is_enable(pdev, "mout_user_mux_aclk_cam1_nocp_133");
		fimc_is_enable(pdev, "mout_user_mux_phyclk_hs0_csis2_rx_byte");
		fimc_is_enable(pdev, "mout_user_mux_aclk_cam1_busperi_334");

		fimc_is_set_rate(pdev, "dout_clkdiv_pclk_cam1_busperi_167", 167 * 1000000);
		fimc_is_set_rate(pdev, "dout_clkdiv_pclk_cam1_busperi_84", 84 * 1000000);
		break;
	default:
		pr_err("channel is invalid(%d)\n", channel);
		ret = -EINVAL;
		goto p_err;
		break;
	}

p_err:
	return ret;
}

int exynos7420_fimc_is_sensor_iclk_off(struct platform_device *pdev,
	u32 scenario,
	u32 channel)
{
	int ret = 0;

	switch (channel) {
	case 0:
		/* CSI */
		exynos7420_fimc_is_csi0_gate(pdev, true);
		/* BNS */
		exynos7420_fimc_is_bns0_gate(pdev, true);
		exynos7420_fimc_is_bns3_gate(pdev, true);
		break;
	case 1:
		/* CSI */
		exynos7420_fimc_is_csi1_gate(pdev, true);
		/* BNS */
		exynos7420_fimc_is_bns1_gate(pdev, true);
		break;
	case 2:
		/* CSI */
		exynos7420_fimc_is_csi2_gate(pdev, true);
		/* BNS */
		exynos7420_fimc_is_bns2_gate(pdev, true);
		break;
	default:
		pr_err("channel is invalid(%d)\n", channel);
		ret = -EINVAL;
		goto p_err;
		break;
	}

	if (scenario == SENSOR_SCENARIO_NORMAL)
		goto p_err;

	switch (channel) {
	case 0:
		/* BUS0 */
		fimc_is_disable(pdev, "gate_aclk_lh_cam0");

		/* CAM0 */
		fimc_is_disable(pdev, "mout_user_mux_aclk_cam0_csis0_690");
		fimc_is_disable(pdev, "mout_user_mux_aclk_cam0_bnsa_690");
		fimc_is_disable(pdev, "mout_user_mux_aclk_cam0_bnsd_690");
		fimc_is_disable(pdev, "mout_user_mux_aclk_cam0_trex_532");
		fimc_is_disable(pdev, "mout_user_mux_aclk_cam0_nocp_133");
		fimc_is_disable(pdev, "mout_user_mux_phyclk_rxbyteclkhs0_s4");
		fimc_is_disable(pdev, "mout_user_mux_phyclk_rxbyteclkhs1_s4");
		fimc_is_disable(pdev, "mout_user_mux_phyclk_rxbyteclkhs2_s4");
		fimc_is_disable(pdev, "mout_user_mux_phyclk_rxbyteclkhs3_s4");
		break;
	case 1:
		/* BUS0 */
		fimc_is_disable(pdev, "gate_aclk_lh_cam0");

		/* CAM0 */
		fimc_is_disable(pdev, "mout_user_mux_aclk_cam0_csis1_174");
		fimc_is_disable(pdev, "mout_user_mux_aclk_cam0_bnsb_690");
		fimc_is_disable(pdev, "mout_user_mux_aclk_cam0_trex_532");
		fimc_is_disable(pdev, "mout_user_mux_aclk_cam0_nocp_133");
		fimc_is_disable(pdev, "mout_user_mux_phyclk_rxbyteclkhs0_s2a");
		break;
	case 2:
		/* BUS0 */
		fimc_is_enable(pdev, "gate_aclk_lh_cam1");

		/* CAM1 */
		fimc_is_disable(pdev, "mout_user_mux_aclk_cam1_bnscsis_133");
		fimc_is_disable(pdev, "mout_user_mux_aclk_cam1_trex_532");
		fimc_is_disable(pdev, "mout_user_mux_aclk_cam1_nocp_133");
		fimc_is_disable(pdev, "mout_user_mux_phyclk_hs0_csis2_rx_byte");
		fimc_is_disable(pdev, "mout_user_mux_aclk_cam1_busperi_334");
		break;
	default:
		pr_err("channel is invalid(%d)\n", channel);
		ret = -EINVAL;
		goto p_err;
		break;
	}

p_err:
	return ret;
}

int exynos7420_fimc_is_sensor_mclk_on(struct platform_device *pdev,
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

	return 0;
}

int exynos7420_fimc_is_sensor_mclk_off(struct platform_device *pdev,
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
int exynos_fimc_is_sensor_iclk_get(struct platform_device *pdev,
	u32 scenario,
	u32 channel)
{
#if defined(CONFIG_SOC_EXYNOS7420)
       exynos7420_fimc_is_sensor_iclk_get(pdev, scenario, channel);
#endif
       return 0;
}

int exynos_fimc_is_sensor_iclk_cfg(struct platform_device *pdev,
	u32 scenario,
	u32 channel)
{
#if defined(CONFIG_SOC_EXYNOS7420)
	exynos7420_fimc_is_sensor_iclk_cfg(pdev, scenario, channel);
#endif
	return 0;
}

int exynos_fimc_is_sensor_iclk_on(struct platform_device *pdev,
	u32 scenario,
	u32 channel)
{
#if defined(CONFIG_SOC_EXYNOS7420)
	exynos7420_fimc_is_sensor_iclk_on(pdev, scenario, channel);
#endif
	return 0;
}

int exynos_fimc_is_sensor_iclk_off(struct platform_device *pdev,
	u32 scenario,
	u32 channel)
{
#if defined(CONFIG_SOC_EXYNOS7420)
	exynos7420_fimc_is_sensor_iclk_off(pdev, scenario, channel);
#endif
	return 0;
}

int exynos_fimc_is_sensor_mclk_on(struct platform_device *pdev,
	u32 scenario,
	u32 channel)
{
#if defined(CONFIG_SOC_EXYNOS7420)
	exynos7420_fimc_is_sensor_mclk_on(pdev, scenario, channel);
#endif
	return 0;
}

int exynos_fimc_is_sensor_mclk_off(struct platform_device *pdev,
	u32 scenario,
	u32 channel)
{
#if defined(CONFIG_SOC_EXYNOS7420)
	exynos7420_fimc_is_sensor_mclk_off(pdev, scenario, channel);
#endif
	return 0;
}
