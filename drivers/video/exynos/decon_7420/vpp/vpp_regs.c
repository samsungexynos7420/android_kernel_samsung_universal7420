/* linux/drivers/video/exynos/decon/vpp/vpp_regs.c
 *
 * Copyright (c) 2011 Samsung Electronics Co., Ltd.
 *		http://www.samsung.com
 *
 * Samsung EXYNOS5 SoC series G-scaler driver
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * by the Free Software Foundation, either version 2 of the License,
 * or (at your option) any later version.
 */

#include <linux/io.h>
#include <linux/delay.h>
#include <linux/ktime.h>
#include <mach/map.h>
#include "vpp_core.h"

#define VPP_SC_RATIO_MAX	((1 << 20) * 8 / 8)
#define VPP_SC_RATIO_7_8	((1 << 20) * 8 / 7)
#define VPP_SC_RATIO_6_8	((1 << 20) * 8 / 6)
#define VPP_SC_RATIO_5_8	((1 << 20) * 8 / 5)
#define VPP_SC_RATIO_4_8	((1 << 20) * 8 / 4)
#define VPP_SC_RATIO_3_8	((1 << 20) * 8 / 3)

extern const s16 h_coef_8t[7][16][8];
extern const s16 v_coef_4t[7][16][4];

int vpp_hw_wait_op_status(struct vpp_dev *vpp)
{
	u32 cfg = 0;

	ktime_t start = ktime_get();

	do {
		cfg = vpp_hw_read(vpp, VG_ENABLE);
		if (!(cfg & (VG_ENABLE_OP_STATUS)))
			return 0;
		udelay(10);
	} while(ktime_us_delta(ktime_get(), start) < 1000000);

	dev_err(DEV, "timeout op_status to idle\n");

	return -EBUSY;
}

void vpp_hw_wait_idle(struct vpp_dev *vpp)
{
	u32 cfg = 0;

	ktime_t start = ktime_get();

	do {
		cfg = vpp_hw_read(vpp, VG_ENABLE);
		if (!(cfg & (VG_ENABLE_OP_STATUS)))
			return;
		dev_warn(DEV, "vpp%d is operating...\n", vpp->id);
		udelay(10);
	} while(ktime_us_delta(ktime_get(), start) < 1000000);

	dev_err(DEV, "timeout op_status to idle\n");
}

int vpp_hw_set_sw_reset(struct vpp_dev *vpp)
{
	u32 cfg = 0;
	ktime_t start;

	vpp_hw_write_mask(vpp, VG_ENABLE, ~0, VG_ENABLE_SRESET);

	start = ktime_get();
	do {
		cfg = vpp_hw_read(vpp, VG_ENABLE);
		if (!(cfg & (VG_ENABLE_SRESET)))
			return 0;
		udelay(10);
	} while(ktime_us_delta(ktime_get(), start) < 1000000);

	dev_err(DEV, "timeout sw reset\n");

	return -EBUSY;
}

void vpp_hw_set_realtime_path(struct vpp_dev *vpp)
{
	vpp_hw_write_mask(vpp, VG_ENABLE, ~0, VG_ENABLE_RT_PATH_EN);
}

void vpp_hw_set_framedone_irq(struct vpp_dev *vpp, bool enable)
{
	u32 val = enable ? ~0 : 0;
	vpp_hw_write_mask(vpp, VG_IRQ, val, VG_IRQ_FRAMEDONE_MASK);
}

void vpp_hw_set_deadlock_irq(struct vpp_dev *vpp, bool enable)
{
	u32 val = enable ? ~0 : 0;
	vpp_hw_write_mask(vpp, VG_IRQ, val, VG_IRQ_DEADLOCK_STATUS_MASK);
}

void vpp_hw_set_read_slave_err_irq(struct vpp_dev *vpp, bool enable)
{
	u32 val = enable ? ~0 : 0;
	vpp_hw_write_mask(vpp, VG_IRQ, val, VG_IRQ_READ_SLAVE_ERROR_MASK);
}

void vpp_hw_set_sfr_update_done_irq(struct vpp_dev *vpp, bool enable)
{
	u32 val = enable ? ~0 : 0;
	vpp_hw_write_mask(vpp, VG_IRQ, val, VG_IRQ_SFR_UPDATE_DONE_MASK);
}

void vpp_hw_set_sfr_update_force(struct vpp_dev *vpp)
{
	vpp_hw_write_mask(vpp, VG_ENABLE, ~0, VG_ENABLE_SFR_UPDATE_FORCE);
}

void vpp_hw_set_enable_interrupt(struct vpp_dev *vpp)
{
	vpp_hw_write_mask(vpp, VG_IRQ, ~0, VG_IRQ_ENABLE);
}

void vpp_hw_set_hw_reset_done_mask(struct vpp_dev *vpp, bool enable)
{
	u32 val = enable ? ~0 : 0;
	vpp_hw_write_mask(vpp, VG_IRQ, val, VG_IRQ_HW_RESET_DONE_MASK);
}

int vpp_hw_set_in_format(struct vpp_dev *vpp)
{
	struct decon_win_config *config = vpp->config;
	u32 cfg = vpp_hw_read(vpp, VG_IN_CON);

	cfg &= ~(VG_IN_CON_IMG_FORMAT_MASK | VG_IN_CON_CHROMINANCE_STRIDE_EN);
	switch(config->format) {
	case DECON_PIXEL_FORMAT_ARGB_8888:
		cfg |= VG_IN_CON_IMG_FORMAT_ARGB8888;
		break;
	case DECON_PIXEL_FORMAT_ABGR_8888:
		cfg |= VG_IN_CON_IMG_FORMAT_ABGR8888;
		break;
	case DECON_PIXEL_FORMAT_RGBA_8888:
		cfg |= VG_IN_CON_IMG_FORMAT_RGBA8888;
		break;
	case DECON_PIXEL_FORMAT_BGRA_8888:
		cfg |= VG_IN_CON_IMG_FORMAT_BGRA8888;
		break;
	case DECON_PIXEL_FORMAT_XRGB_8888:
		cfg |= VG_IN_CON_IMG_FORMAT_XRGB8888;
		break;
	case DECON_PIXEL_FORMAT_XBGR_8888:
		cfg |= VG_IN_CON_IMG_FORMAT_XBGR8888;
		break;
	case DECON_PIXEL_FORMAT_RGBX_8888:
		cfg |= VG_IN_CON_IMG_FORMAT_RGBX8888;
		break;
	case DECON_PIXEL_FORMAT_BGRX_8888:
		cfg |= VG_IN_CON_IMG_FORMAT_BGRX8888;
		break;
	case DECON_PIXEL_FORMAT_RGB_565:
		cfg |= VG_IN_CON_IMG_FORMAT_RGB565;
		break;
	case DECON_PIXEL_FORMAT_NV16:
		cfg |= VG_IN_CON_IMG_FORMAT_YUV422_2P;
		break;
	case DECON_PIXEL_FORMAT_NV61:
		cfg |= VG_IN_CON_IMG_FORMAT_YVU422_2P;
		break;
	case DECON_PIXEL_FORMAT_NV12:
	case DECON_PIXEL_FORMAT_NV12M:
		cfg |= VG_IN_CON_IMG_FORMAT_YUV420_2P;
		break;
	case DECON_PIXEL_FORMAT_NV21:
	case DECON_PIXEL_FORMAT_NV21M:
		cfg |= VG_IN_CON_IMG_FORMAT_YVU420_2P;
		break;
	default:
		dev_err(DEV, "Unsupported Format\n");
		return -EINVAL ;
	}

	vpp_hw_write(vpp, VG_IN_CON, cfg);

	return 0;
}

void vpp_hw_set_h_coef(struct vpp_dev *vpp, u32 h_ratio)
{
	int i, j, k, sc_ratio;

	if (h_ratio <= VPP_SC_RATIO_MAX)
		sc_ratio = 0;
	else if (h_ratio <= VPP_SC_RATIO_7_8)
		sc_ratio = 1;
	else if (h_ratio <= VPP_SC_RATIO_6_8)
		sc_ratio = 2;
	else if (h_ratio <= VPP_SC_RATIO_5_8)
		sc_ratio = 3;
	else if (h_ratio <= VPP_SC_RATIO_4_8)
		sc_ratio = 4;
	else if (h_ratio <= VPP_SC_RATIO_3_8)
		sc_ratio = 5;
	else
		sc_ratio = 6;

	for (i = 0; i < 9; i++) {
		for (j = 0; j < 8; j++) {
			for (k = 0; k < 2; k++) {
				vpp_hw_write(vpp, VG_H_COEF(i, j, k),
						h_coef_8t[sc_ratio][i][j]);
			}
		}
	}
}

void vpp_hw_set_v_coef(struct vpp_dev *vpp, u32 v_ratio)
{
	int i, j, k, sc_ratio;

	if (v_ratio <= VPP_SC_RATIO_MAX)
		sc_ratio = 0;
	else if (v_ratio <= VPP_SC_RATIO_7_8)
		sc_ratio = 1;
	else if (v_ratio <= VPP_SC_RATIO_6_8)
		sc_ratio = 2;
	else if (v_ratio <= VPP_SC_RATIO_5_8)
		sc_ratio = 3;
	else if (v_ratio <= VPP_SC_RATIO_4_8)
		sc_ratio = 4;
	else if (v_ratio <= VPP_SC_RATIO_3_8)
		sc_ratio = 5;
	else
		sc_ratio = 6;

	for (i = 0; i < 9; i++) {
		for (j = 0; j < 4; j++) {
			for (k = 0; k < 2; k++) {
				vpp_hw_write(vpp, VG_V_COEF(i, j, k),
						v_coef_4t[sc_ratio][i][j]);
			}
		}
	}
}

int vpp_hw_set_rotation(struct vpp_dev *vpp)
{
	struct decon_win_config *config = vpp->config;

	vpp_hw_write_mask(vpp, VG_IN_CON, config->vpp_parm.rot << 8, VG_IN_CON_IN_ROTATION_MASK);

	return 0;
}

void vpp_hw_set_scale_ratio(struct vpp_dev *vpp)
{
	struct decon_win_config *config = vpp->config;
	struct vpp_fraction *fr = &vpp->fract_val;
	u32 h_ratio, v_ratio = 0;
	u32 tmp_width, tmp_height = 0;
	u32 tmp_fr_w, tmp_fr_h = 0;

	if (is_rotation(config)) {
		tmp_width = config->src.h;
		tmp_height = config->src.w;
		tmp_fr_w = fr->h;
		tmp_fr_h = fr->w;
	} else {
		tmp_width = config->src.w;
		tmp_height = config->src.h;
		tmp_fr_w = fr->w;
		tmp_fr_h = fr->h;
	}

	h_ratio = ((tmp_width << 20) + tmp_fr_w) / config->dst.w;
	v_ratio = ((tmp_height << 20) + tmp_fr_h) / config->dst.h;

	if (vpp->h_ratio != h_ratio) {
		vpp_hw_write(vpp, VG_H_RATIO, h_ratio);
		vpp_hw_set_h_coef(vpp, h_ratio);
	}

	if (vpp->v_ratio != v_ratio) {
		vpp_hw_write(vpp, VG_V_RATIO, v_ratio);
		vpp_hw_set_v_coef(vpp, v_ratio);
	}

	vpp->h_ratio = h_ratio;
	vpp->v_ratio = v_ratio;

	dev_dbg(DEV, "h_ratio : %#x, v_ratio : %#x\n",
			h_ratio, v_ratio);
}

void vpp_hw_set_in_buf_addr(struct vpp_dev *vpp)
{
	struct decon_device *decon = get_decon_drvdata(0);
	struct vpp_params *vpp_parm = &vpp->config->vpp_parm;
	dma_addr_t cb_addr = 0;
	u32 addr;

	dev_dbg(DEV, "y : %pa, cb : %pa, cr : %pa\n",
		&vpp_parm->addr[0], &vpp_parm->addr[1], &vpp_parm->addr[2]);

	vpp_hw_write(vpp, VG_BASE_ADDR_Y(0), vpp_parm->addr[0]);
	vpp_hw_write(vpp, VG_BASE_ADDR_CB(0), vpp_parm->addr[1]);
	if (vpp->id == 2)
		cb_addr = decon->vgr0_cb_addr;
	else if (vpp->id == 3)
		cb_addr = decon->vgr1_cb_addr;
	if(cb_addr > 0) {
		addr = vpp_hw_read(vpp, VG_BASE_ADDR_CB(0));
		if(addr != (u32)cb_addr)
			dev_err(DEV, "vpp CB_ADDR is incorrect(0x%x, 0x%x\n",
					addr, (u32)cb_addr);
	}
}

void vpp_hw_set_in_size(struct vpp_dev *vpp)
{
	struct decon_win_config *config = vpp->config;
	u32 cfg = 0;

	/* source offset */
	cfg = VG_SRC_OFFSET_X(config->src.x) | VG_SRC_OFFSET_Y(config->src.y);
	vpp_hw_write(vpp, VG_SRC_OFFSET, cfg);

	/* source full(alloc) size */
	cfg = VG_SRC_SIZE_WIDTH(config->src.f_w) | VG_SRC_SIZE_HEIGHT(config->src.f_h);
	vpp_hw_write(vpp, VG_SRC_SIZE, cfg);

	/* source cropped size */
	cfg = VG_IMG_SIZE_WIDTH(config->src.w) | VG_IMG_SIZE_HEIGHT(config->src.h);
	vpp_hw_write(vpp, VG_IMG_SIZE, cfg);

	if (vpp->fract_val.w)
		config->src.w--;
	if (vpp->fract_val.h)
		config->src.h--;

	/* fraction position */
	vpp_hw_write(vpp, VG_YHPOSITION0, vpp->fract_val.y_x);
	vpp_hw_write(vpp, VG_YVPOSITION0, vpp->fract_val.y_y);
	vpp_hw_write(vpp, VG_CHPOSITION0, vpp->fract_val.c_x);
	vpp_hw_write(vpp, VG_CVPOSITION0, vpp->fract_val.c_y);
}

void vpp_hw_set_in_block_size(struct vpp_dev *vpp, bool enable)
{
	struct decon_win_config *config = vpp->config;
	u32 cfg = 0;

	if (!enable) {
		vpp_hw_write_mask(vpp, VG_IN_CON, 0, VG_IN_CON_BLOCKING_FEATURE_EN);
		return;
	}

	/* blocking area offset */
	cfg = VG_BLK_OFFSET_X(config->block_area.x) | VG_BLK_OFFSET_Y(config->block_area.y);
	vpp_hw_write(vpp, VG_BLK_OFFSET, cfg);

	/* blocking area size */
	cfg = VG_BLK_SIZE_WIDTH(config->block_area.w) | VG_BLK_SIZE_HEIGHT(config->block_area.h);
	vpp_hw_write(vpp, VG_BLK_SIZE, cfg);

	vpp_hw_write_mask(vpp, VG_IN_CON, ~0, VG_IN_CON_BLOCKING_FEATURE_EN);

	dev_dbg(DEV, "block x : %d, y : %d, w : %d, h : %d\n",
			config->block_area.x, config->block_area.y,
			config->block_area.w, config->block_area.h);
}

void vpp_hw_set_out_size(struct vpp_dev *vpp)
{
	struct decon_win_config *config = vpp->config;
	u32 cfg = 0;

	/* destination scaled size */
	cfg = VG_SCALED_SIZE_WIDTH(config->dst.w) | VG_SCALED_SIZE_HEIGHT(config->dst.h);
	vpp_hw_write(vpp, VG_SCALED_SIZE, cfg);
}

void vpp_hw_set_rgb_type(struct vpp_dev *vpp)
{
	u32 cfg = VG_OUT_CON_RGB_TYPE_601_WIDE;

	vpp_hw_write(vpp, VG_OUT_CON, cfg);
}

void vpp_hw_set_plane_alpha(struct vpp_dev *vpp)
{
	struct decon_win_config *config = vpp->config;

	if (config->plane_alpha > 0xFF)
		dev_warn(DEV, "%d is too much value\n",
				config->plane_alpha);
	vpp_hw_write_mask(vpp, VG_OUT_CON, VG_OUT_CON_FRAME_ALPHA(config->plane_alpha),
			VG_OUT_CON_FRAME_ALPHA_MASK);
}

void vpp_hw_set_plane_alpha_fixed(struct vpp_dev *vpp)
{
	vpp_hw_write_mask(vpp, VG_OUT_CON, VG_OUT_CON_FRAME_ALPHA(0xFF),
			VG_OUT_CON_FRAME_ALPHA_MASK);
}

void vpp_hw_set_smart_if_pix_num(struct vpp_dev *vpp)
{
	struct decon_win_config *config = vpp->config;

	vpp_hw_write(vpp, VG_SMART_IF_PIXEL_NUM, config->dst.w * config->dst.h);
}

void vpp_hw_set_lookup_table(struct vpp_dev *vpp)
{
	vpp_hw_write(vpp, VG_QOS_LUT07_00, 0x44444444);
	vpp_hw_write(vpp, VG_QOS_LUT15_08, 0x44444444);
}

void vpp_hw_set_dynamic_clock_gating(struct vpp_dev *vpp)
{
	vpp_hw_write(vpp, VG_DYNAMIC_GATING_ENABLE, 0x3F);
}

