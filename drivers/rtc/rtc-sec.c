/*
 * rtc-sec.c
 *
 * Copyright (c) 2012 Samsung Electronics Co., Ltd
 *              http://www.samsung.com
 *
 *  This program is free software; you can redistribute  it and/or modify it
 *  under  the terms of  the GNU General  Public License as published by the
 *  Free Software Foundation;  either version 2 of the  License, or (at your
 *  option) any later version.
 *
 *  2013-12-11  Performance improvements and code clean up by
 *		Minsung Kim <ms925.kim@samsung.com>
 *
 */
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/gpio.h>
#include <linux/rtc.h>
#include <linux/io.h>
#include <linux/delay.h>
#include <linux/slab.h>
#include <linux/regmap.h>
#include <linux/platform_device.h>
#include <linux/mfd/samsung/core.h>
#include <linux/mfd/samsung/rtc.h>
#include <linux/mfd/samsung/irq.h>
#include <linux/mfd/samsung/s2mps11.h>
#include <linux/mfd/samsung/s2mps13.h>
#include <linux/mfd/samsung/s2mps15.h>
#include <linux/mfd/samsung/s2mpu03.h>
#include <mach/cpufreq.h>
#if defined(CONFIG_RTC_ALARM_BOOT)
#include <linux/reboot.h>
#include <linux/wakelock.h>
#endif

#ifdef CONFIG_EXYNOS_MBOX
#include <mach/apm-exynos.h>
#endif

#if 0 //#ifdef CONFIG_BATTERY_SWELLING_SELF_DISCHARGING
#include <linux/sec_batt_selfdchg_common.h>
#endif

struct s2m_rtc_info {
	struct device		*dev;
	struct sec_pmic_dev	*iodev;
	struct rtc_device	*rtc_dev;
	struct mutex		lock;
	struct work_struct	irq_work;
	int			irq;
#if defined(CONFIG_RTC_ALARM_BOOT)
	int alarm_boot_irq;
	bool lpm_mode;
	bool alarm_irq_flag;
	struct wake_lock alarm_wake_lock;
#endif
#if 0 //#ifdef CONFIG_BATTERY_SWELLING_SELF_DISCHARGING
	bool dchg_check_rtc_set;
#endif
	int			smpl_irq;
	bool			use_irq;
	u8 			*adc_val;
	u8			*adc_reg;
	u8			adc_ctrl1;
	bool			wtsr_en;
	bool			smpl_en;
	bool			alarm_enabled;
	u8			update_reg;
	bool			use_alarm_workaround;
	bool			alarm_check;
	bool			udr_updated;
	u8			wudr_mask;
	u8			audr_mask;
	int				smpl_warn_info;
};

static const unsigned int s2mps15_buck_coeffs[11][2] = { {15625, 17857}, {46875, 53571},
	{15625, 17857}, {15625, 17857}, {15625, 17857}, {31250, 35714},
	{15625, 17857}, {15625, 15625}, {15625, 15625}, {15625, 17857},
	{15625, 17857} };

static const unsigned int s2mps15_ldo_coeff = 4688;

static struct wakeup_source *rtc_ws;

enum S2M_RTC_OP {
	S2M_RTC_READ,
	S2M_RTC_WRITE_TIME,
	S2M_RTC_WRITE_ALARM,
};

#if 0 //#if defined(CONFIG_BATTERY_SWELLING_SELF_DISCHARGING)
#define RTC_BWAKEUP_AMIN 5
#define RTC_BWAKEUP_ALOOP_MIN 60
static u8 rtc_balarm_min_for_dischg = 0;
#endif

static void s2m_data_to_tm(u8 *data, struct rtc_time *tm)
{
	tm->tm_sec = data[RTC_SEC] & 0x7f;
	tm->tm_min = data[RTC_MIN] & 0x7f;
	tm->tm_hour = data[RTC_HOUR] & 0x1f;
	tm->tm_wday = __fls(data[RTC_WEEKDAY] & 0x7f);
	tm->tm_mday = data[RTC_DATE] & 0x1f;
	tm->tm_mon = (data[RTC_MONTH] & 0x0f) - 1;
	tm->tm_year = (data[RTC_YEAR] & 0x7f) + 100;
	tm->tm_yday = 0;
	tm->tm_isdst = 0;
}

static int s2m_tm_to_data(struct rtc_time *tm, u8 *data)
{
	data[RTC_SEC] = tm->tm_sec;
	data[RTC_MIN] = tm->tm_min;

	if (tm->tm_hour >= 12)
		data[RTC_HOUR] = tm->tm_hour | HOUR_PM_MASK;
	else
		data[RTC_HOUR] = tm->tm_hour;

	data[RTC_WEEKDAY] = BIT(tm->tm_wday);
	data[RTC_DATE] = tm->tm_mday;
	data[RTC_MONTH] = tm->tm_mon + 1;
	data[RTC_YEAR] = tm->tm_year > 100 ? (tm->tm_year - 100) : 0 ;

	if (tm->tm_year < 100) {
		pr_warn("%s: SEC RTC cannot handle the year %d\n", __func__,
				1900 + tm->tm_year);
		return -EINVAL;
	}
	return 0;
}

static int s2m_rtc_update(struct s2m_rtc_info *info,
				 enum S2M_RTC_OP op)
{
	u8 data;
	int ret;

	if (!info || !info->iodev) {
		pr_err("%s: Invalid argument\n", __func__);
		return -EINVAL;
	}

	switch (op) {
	case S2M_RTC_READ:
		data = RTC_RUDR_MASK;
		break;
	case S2M_RTC_WRITE_TIME:
		data = info->wudr_mask;
		break;
	case S2M_RTC_WRITE_ALARM:
		if (info->iodev->device_type == S2MPS15X && SEC_PMIC_REV(info->iodev))
			data = info->audr_mask;
		else if (info->iodev->device_type == S2MPU03X)
			data = info->audr_mask;
		else if (info->udr_updated)
			data = info->audr_mask | info->wudr_mask;
		else
			data = RTC_RUDR_MASK | info->wudr_mask;
		break;
	default:
		dev_err(info->dev, "%s: invalid op(%d)\n", __func__, op);
		return -EINVAL;
	}

	data |= info->update_reg;

	ret = sec_rtc_write(info->iodev, S2M_RTC_UPDATE, data);
	if (ret < 0)
		dev_err(info->dev, "%s: fail to write update reg(%d,%u)\n",
				__func__, ret, data);
	else
		usleep_range(1000, 1000);

	return ret;
}

static int s2m_rtc_read_time(struct device *dev, struct rtc_time *tm)
{
	struct s2m_rtc_info *info = dev_get_drvdata(dev);
	u8 data[NR_RTC_CNT_REGS];
	int ret;

	mutex_lock(&info->lock);
	ret = s2m_rtc_update(info, S2M_RTC_READ);
	if (ret < 0)
		goto out;

	ret = sec_rtc_bulk_read(info->iodev, S2M_RTC_SEC, NR_RTC_CNT_REGS,
			data);
	if (ret < 0) {
		dev_err(info->dev, "%s: fail to read time reg(%d)\n", __func__,
			ret);
		goto out;
	}

	dev_info(info->dev, "%s: %d-%02d-%02d %02d:%02d:%02d(0x%02x)%s\n",
			__func__, data[RTC_YEAR] + 2000, data[RTC_MONTH],
			data[RTC_DATE], data[RTC_HOUR] & 0x1f, data[RTC_MIN],
			data[RTC_SEC], data[RTC_WEEKDAY],
			data[RTC_HOUR] & HOUR_PM_MASK ? "PM" : "AM");

	s2m_data_to_tm(data, tm);
	ret = rtc_valid_tm(tm);
out:
	mutex_unlock(&info->lock);
	return ret;
}

static int s2m_rtc_set_time(struct device *dev, struct rtc_time *tm)
{
	struct s2m_rtc_info *info = dev_get_drvdata(dev);
	u8 data[NR_RTC_CNT_REGS];
	int ret;

	ret = s2m_tm_to_data(tm, data);
	if (ret < 0)
		return ret;

	dev_info(info->dev, "%s: %d-%02d-%02d %02d:%02d:%02d(0x%02x)%s\n",
			__func__, data[RTC_YEAR] + 2000, data[RTC_MONTH],
			data[RTC_DATE], data[RTC_HOUR] & 0x1f, data[RTC_MIN],
			data[RTC_SEC], data[RTC_WEEKDAY],
			data[RTC_HOUR] & HOUR_PM_MASK ? "PM" : "AM");

	mutex_lock(&info->lock);
	ret = sec_rtc_bulk_write(info->iodev, S2M_RTC_SEC, NR_RTC_CNT_REGS,
			data);
	if (ret < 0) {
		dev_err(info->dev, "%s: fail to write time reg(%d)\n", __func__,
			ret);
		goto out;
	}

	ret = s2m_rtc_update(info, S2M_RTC_WRITE_TIME);
out:
	mutex_unlock(&info->lock);
	return ret;
}

/* This is a workaround for the problem that RTC TIME is overwirted by write
 * buffer when setting RTC ALARM. It is quite rare but it does happen. The root
 * cuase is that clear signal of RUDR & WUDR is 1 clock delay while it should be
 * 2 clock delay.
 */
static int s2m_rtc_check_rtc_time(struct s2m_rtc_info *info)
{
	u8 data[NR_RTC_CNT_REGS];
	struct rtc_time tm;
	struct timeval sys_time;
	unsigned long rtc_time;
	int ret;

	/* Read RTC TIME */
	ret = s2m_rtc_update(info, S2M_RTC_READ);
	if (ret < 0)
		goto out;

	ret = sec_rtc_bulk_read(info->iodev, S2M_RTC_SEC, NR_RTC_CNT_REGS,
			data);
	if (ret < 0) {
		dev_err(info->dev, "%s: fail to read time reg(%d)\n", __func__,
			ret);
		goto out;
	}

	/* Get system time */
	do_gettimeofday(&sys_time);

	/* Convert RTC TIME to seconds since 01-01-1970 00:00:00. */
	s2m_data_to_tm(data, &tm);
	rtc_tm_to_time(&tm, &rtc_time);

	if (abs(rtc_time - sys_time.tv_sec) > 2) {
		/* Set RTC TIME */
		rtc_time_to_tm(sys_time.tv_sec, &tm);
		ret = s2m_tm_to_data(&tm, data);
		if (ret < 0) {
			dev_err(info->dev, "%s: fail to tm_to_data(%d)\n",
					__func__, ret);
			goto out;
		}

		ret = sec_rtc_bulk_write(info->iodev, S2M_RTC_SEC,
				NR_RTC_CNT_REGS, data);
		if (ret < 0) {
			dev_err(info->dev, "%s: fail to write time reg(%d)\n",
					__func__, ret);
			goto out;
		}

		ret = s2m_rtc_update(info, S2M_RTC_WRITE_TIME);

		dev_warn(info->dev, "%s: adjust RTC TIME: sys_time: %lu, "
				"rtc_time: %lu\n", __func__, sys_time.tv_sec,
				rtc_time);

		dev_info(info->dev, "%s: %d-%02d-%02d %02d:%02d:%02d(0x%02x)%s\n",
				__func__, data[RTC_YEAR] + 2000, data[RTC_MONTH],
				data[RTC_DATE], data[RTC_HOUR] & 0x1f, data[RTC_MIN],
				data[RTC_SEC], data[RTC_WEEKDAY],
				data[RTC_HOUR] & HOUR_PM_MASK ? "PM" : "AM");
	}
out:
	return ret;
}

static int s2m_rtc_read_alarm(struct device *dev, struct rtc_wkalrm *alrm)
{
	struct s2m_rtc_info *info = dev_get_drvdata(dev);
	u8 data[NR_RTC_CNT_REGS];
	u32 reg, val;
	int ret;

	mutex_lock(&info->lock);
	ret = s2m_rtc_update(info, S2M_RTC_READ);
	if (ret < 0)
		goto out;

	ret = sec_rtc_bulk_read(info->iodev, S2M_ALARM0_SEC, NR_RTC_CNT_REGS,
			data);
	if (ret < 0) {
		dev_err(info->dev, "%s:%d fail to read alarm reg(%d)\n",
			__func__, __LINE__, ret);
		goto out;
	}

	s2m_data_to_tm(data, &alrm->time);

	dev_info(info->dev, "%s: %d-%02d-%02d %02d:%02d:%02d(%d)\n", __func__,
			alrm->time.tm_year + 1900, alrm->time.tm_mon + 1,
			alrm->time.tm_mday, alrm->time.tm_hour,
			alrm->time.tm_min, alrm->time.tm_sec,
			alrm->time.tm_wday);

	alrm->enabled = info->alarm_enabled;
	alrm->pending = 0;

	switch (info->iodev->device_type) {
	case S2MPS11X:
		reg = S2MPS11_REG_ST2;
		break;
	case S2MPS13X:
		reg = S2MPS13_REG_ST2;
		break;
	case S2MPS15X:
		reg = S2MPS15_REG_ST2;
		break;
	case S2MPU03X:
		reg = S2MPU03_REG_ST2;
		break;
	default:
		/* If this happens the core funtion has a problem */
		BUG();
	}

	ret = sec_reg_read(info->iodev, reg, &val);
	if (ret < 0) {
		dev_err(info->dev, "%s:%d fail to read STATUS2 reg(%d)\n",
			__func__, __LINE__, ret);
		goto out;
	}

	if (val & RTCA0E)
		alrm->pending = 1;
out:
	mutex_unlock(&info->lock);
	return ret;
}

static int s2m_rtc_set_alarm_enable(struct s2m_rtc_info *info, bool enabled)
{
	if (!info->use_irq)
		return -EPERM;

	if (enabled && !info->alarm_enabled) {
		info->alarm_enabled = true;
		enable_irq(info->irq);
	} else if (!enabled && info->alarm_enabled) {
		info->alarm_enabled = false;
		disable_irq(info->irq);
	}
	return 0;
}

static int s2m_rtc_set_alarm(struct device *dev, struct rtc_wkalrm *alrm)
{
	struct s2m_rtc_info *info = dev_get_drvdata(dev);
	u8 data[NR_RTC_CNT_REGS];
	int ret, i;

	mutex_lock(&info->lock);
#if 0 //#ifdef CONFIG_BATTERY_SWELLING_SELF_DISCHARGING
	if (info->dchg_check_rtc_set) {
		pr_err("[SDCHG][%s] already set discharging rtc for bootloader\n", __func__);
		ret = -EPERM;
		goto out;
	}
#endif
	ret = s2m_tm_to_data(&alrm->time, data);
	if (ret < 0)
		goto out;

	dev_info(info->dev, "%s: %d-%02d-%02d %02d:%02d:%02d(0x%02x)%s\n",
			__func__, data[RTC_YEAR] + 2000, data[RTC_MONTH],
			data[RTC_DATE], data[RTC_HOUR] & 0x1f, data[RTC_MIN],
			data[RTC_SEC], data[RTC_WEEKDAY],
			data[RTC_HOUR] & HOUR_PM_MASK ? "PM" : "AM");

	if (info->alarm_check) {
		for (i = 0; i < NR_RTC_CNT_REGS; i++)
			data[i] &= ~ALARM_ENABLE_MASK;

		ret = sec_rtc_bulk_write(info->iodev, S2M_ALARM0_SEC, NR_RTC_CNT_REGS,
				data);
		if (ret < 0) {
			dev_err(info->dev, "%s: fail to disable alarm reg(%d)\n",
				__func__, ret);
			goto out;
		}

		ret = s2m_rtc_update(info, S2M_RTC_WRITE_ALARM);
		if (ret < 0)
			goto out;
	}

	for (i = 0; i < NR_RTC_CNT_REGS; i++)
		data[i] |= ALARM_ENABLE_MASK;

	ret = sec_rtc_bulk_write(info->iodev, S2M_ALARM0_SEC, NR_RTC_CNT_REGS,
			data);
	if (ret < 0) {
		dev_err(info->dev, "%s: fail to write alarm reg(%d)\n",
			__func__, ret);
		goto out;
	}

	ret = s2m_rtc_update(info, S2M_RTC_WRITE_ALARM);
	if (ret < 0)
		goto out;

	if (info->use_alarm_workaround) {
		ret = s2m_rtc_check_rtc_time(info);
		if (ret < 0)
			goto out;
	}

	ret = s2m_rtc_set_alarm_enable(info, alrm->enabled);

out:
	mutex_unlock(&info->lock);
	return ret;
}

#if defined(CONFIG_RTC_ALARM_BOOT)
static inline int s2m_rtc_set_update_reg(struct s2m_rtc_info *info,enum S2M_RTC_OP op)
{
	int ret;
	unsigned int data;

	ret = sec_rtc_read(info->iodev, S2M_RTC_UPDATE, &data);
	if (ret < 0)
		return ret;

	switch (op) {
	case S2M_RTC_READ:
		data |= RTC_RUDR_MASK;
		break;
	case S2M_RTC_WRITE_TIME:
		data |= info->wudr_mask;
		break;
	case S2M_RTC_WRITE_ALARM:
		data |= info->audr_mask;
		break;
	default:
		dev_err(info->dev, "%s: invalid op(%d)\n", __func__, op);
		return -EINVAL;
	}

	ret = sec_rtc_write(info->iodev, S2M_RTC_UPDATE, (char)data);

	if (ret < 0) {
		dev_err(info->dev, "%s: fail to write update reg(%d)\n",
				__func__, ret);
	} else {
		usleep_range(1000, 1000);
	}

	return ret;
}

static int s2m_rtc_stop_alarm_boot(struct s2m_rtc_info *info)
{
	u8 data[7];
	int ret, i;
	struct rtc_time tm;

	ret = sec_rtc_bulk_read(info->iodev, S2M_ALARM1_SEC, 7, data);
	if (ret < 0)
		return ret;

	s2m_data_to_tm(data, &tm);

	printk(KERN_INFO "%s: %d/%d/%d %d:%d:%d(%d)\n", __func__,
		1900 + tm.tm_year, 1 + tm.tm_mon, tm.tm_mday,
		tm.tm_hour, tm.tm_min, tm.tm_sec, tm.tm_wday);

	for (i = 0; i < 7; i++)
		data[i] &= ~ALARM_ENABLE_MASK;

	ret = sec_rtc_bulk_write(info->iodev, S2M_ALARM1_SEC, 7, data);
	if (ret < 0)
		return ret;

	ret = s2m_rtc_set_update_reg(info, S2M_RTC_WRITE_ALARM);

	return ret;
}

static int s2m_rtc_start_alarm_boot(struct s2m_rtc_info *info)
{
	int ret;
	u8 data[7];
	struct rtc_time tm;

	ret = sec_rtc_bulk_read(info->iodev, S2M_ALARM1_SEC, 7, data);
	if (ret < 0)
		return ret;

	s2m_data_to_tm(data, &tm);

	printk(KERN_INFO "%s: %d/%d/%d %d:%d:%d(%d)\n", __func__,
		1900 + tm.tm_year, 1 + tm.tm_mon, tm.tm_mday,
		tm.tm_hour, tm.tm_min, tm.tm_sec, tm.tm_wday);

	data[RTC_SEC] |= ALARM_ENABLE_MASK;
	data[RTC_MIN] |= ALARM_ENABLE_MASK;
	data[RTC_HOUR] |= ALARM_ENABLE_MASK;
	data[RTC_WEEKDAY] &= 0x00;
	if (data[RTC_DATE] & 0x1f)
		data[RTC_DATE] |= ALARM_ENABLE_MASK;
	if (data[RTC_MONTH] & 0xf)
		data[RTC_MONTH] |= ALARM_ENABLE_MASK;
	if (data[RTC_YEAR] & 0x7f)
		data[RTC_YEAR] |= ALARM_ENABLE_MASK;

	ret = sec_rtc_bulk_write(info->iodev, S2M_ALARM1_SEC, 7, data);
	if (ret < 0)
		return ret;

	ret = s2m_rtc_set_update_reg(info, S2M_RTC_WRITE_ALARM);

	return ret;
}

static int s2m_rtc_set_alarm_boot(struct device *dev,
					struct rtc_wkalrm *alrm)
{
	struct s2m_rtc_info *info = dev_get_drvdata(dev);
	u8 data[7];
	int ret;

	mutex_lock(&info->lock);

	s2m_tm_to_data(&alrm->time, data);

	dev_info(info->dev, "%s: %d-%02d-%02d %02d:%02d:%02d(0x%02x)%s\n",
			__func__, data[RTC_YEAR] + 2000, data[RTC_MONTH],
			data[RTC_DATE], data[RTC_HOUR] & 0x1f, data[RTC_MIN],
			data[RTC_SEC], data[RTC_WEEKDAY],
			data[RTC_HOUR] & HOUR_PM_MASK ? "PM" : "AM");

	ret = s2m_rtc_stop_alarm_boot(info);
	if (ret < 0)
		return ret;

	ret = sec_rtc_read(info->iodev, S2M_RTC_UPDATE, &info->update_reg);
	if (ret < 0)
	{
		printk(KERN_INFO "%s: read fail \n", __func__);
		return ret;
	}

	if (alrm->enabled)
		info->update_reg |= RTC_WAKE_MASK;
	else
		info->update_reg &= ~RTC_WAKE_MASK;

	ret = sec_rtc_write(info->iodev, S2M_RTC_UPDATE, (char)info->update_reg);

	if (ret < 0) {
		dev_err(info->dev, "%s: fail to write update reg(%d)\n",
				__func__, ret);
	} else {
		usleep_range(1000, 1000);
	}

	ret = sec_rtc_bulk_write(info->iodev, S2M_ALARM1_SEC, 7, data);
	if (ret < 0)
		return ret;

	ret = s2m_rtc_set_update_reg(info, S2M_RTC_WRITE_ALARM);

	if (ret < 0)
		return ret;

	if (alrm->enabled)
		ret = s2m_rtc_start_alarm_boot(info);

	mutex_unlock(&info->lock);

	return ret;
}

static int s2m_rtc_get_alarm_boot(struct device *dev,
				      struct rtc_wkalrm *alrm)
{
	struct s2m_rtc_info *info = dev_get_drvdata(dev);

	if( info->alarm_irq_flag)
		alrm->enabled = 0x1;
	else
		alrm->enabled = 0x0;
	printk("s2m_rtc_get_alarm_boot : %d, %d\n",
						info->lpm_mode, alrm->enabled);
	return info->lpm_mode;
}
#endif

#if 0 //#if defined(CONFIG_BATTERY_SWELLING_SELF_DISCHARGING)
static inline int s2m_rtc_update_reg_dischg(struct s2m_rtc_info *info,
                      enum S2M_RTC_OP op)
{
	int ret;
	unsigned int data;

	ret = sec_rtc_read(info->iodev, S2M_RTC_UPDATE, &data);
	if (ret < 0)
		return ret;

	switch (op) {
	case S2M_RTC_READ:
		data |= RTC_RUDR_MASK;
		break;
	case S2M_RTC_WRITE_TIME:
		data |= info->wudr_mask;
		break;
	case S2M_RTC_WRITE_ALARM:
		data |= info->audr_mask;
		break;
	default:
		dev_err(info->dev, "%s: invalid op(%d)\n", __func__, op);
		return -EINVAL;
	}

	ret = sec_rtc_write(info->iodev, S2M_RTC_UPDATE, (char)data);

	if (ret < 0) {
		dev_err(info->dev, "%s: fail to write update reg(%d)\n",
				__func__, ret);
	} else {
		usleep_range(1000, 1000);
	}

	return ret;
}

static int s2m_rtc_stop_balarm_dischg(struct s2m_rtc_info *info)
{
	u8 data[7];
	int ret,i;
	struct rtc_time tm;

	ret = sec_rtc_bulk_read(info->iodev, S2M_ALARM0_SEC, 7, data);
	if (ret < 0)
		return ret;

	s2m_data_to_tm(data, &tm);

	printk(KERN_INFO "%s: %d/%d/%d %d:%d:%d(%d)\n", __func__,
		1900 + tm.tm_year, 1 + tm.tm_mon, tm.tm_mday,
		tm.tm_hour, tm.tm_min, tm.tm_sec, tm.tm_wday);

	for (i = 0; i < 7; i++)
		data[i] &= ~ALARM_ENABLE_MASK;

	ret = sec_rtc_bulk_write(info->iodev, S2M_ALARM0_SEC, 7, data);
	if (ret < 0)
		return ret;

	ret = s2m_rtc_update_reg_dischg(info, S2M_RTC_WRITE_ALARM);

	return ret;
}

static int s2m_rtc_start_balarm_dischg(struct s2m_rtc_info *info)
{
	int ret;
	u8 data[7];
	struct rtc_time tm;

	ret = sec_rtc_bulk_read(info->iodev, S2M_ALARM0_SEC, 7, data);
	if (ret < 0)
		return ret;

	s2m_data_to_tm(data, &tm);

	printk(KERN_INFO "%s: %d/%d/%d %d:%d:%d(%d)\n", __func__,
		1900 + tm.tm_year, 1 + tm.tm_mon, tm.tm_mday,
		tm.tm_hour, tm.tm_min, tm.tm_sec, tm.tm_wday);

	//DISCHG Algorithm must run all the time
	data[RTC_MIN] |= ALARM_ENABLE_MASK;
	printk(KERN_INFO "%s data[RTC_MIN] = 0x%02x\n",__func__, data[RTC_MIN]);

	ret = sec_rtc_bulk_write(info->iodev, S2M_ALARM0_MIN, 1, &data[RTC_MIN]);
	if (ret < 0)
		return ret;

	ret = s2m_rtc_update_reg_dischg(info, S2M_RTC_WRITE_ALARM);

	ret = sec_rtc_bulk_read(info->iodev, S2M_ALARM0_SEC, 7, data);
	if (ret < 0)
		return ret;
	
	s2m_data_to_tm(data, &tm);

	printk(KERN_INFO "%s: %d/%d/%d %d:%d:%d(%d)\n", __func__,
		1900 + tm.tm_year, 1 + tm.tm_mon, tm.tm_mday,
		tm.tm_hour, tm.tm_min, tm.tm_sec, tm.tm_wday);
	printk(KERN_INFO "%s data[RTC_MIN] = 0x%02x\n",__func__,	data[RTC_MIN]);

	return ret;
}

static int s2m_rtc_set_balarm_dischg_only(struct s2m_rtc_info *info)
{
	int ret;
	u8 rtc_balarm_min;	
	u8 rtcwake;
	u8 data[NR_RTC_CNT_REGS];

#if defined(CONFIG_RTC_ALARM_BOOT)
	unsigned long alarm_time;
	unsigned long rtc_time;
	struct rtc_time temp_rtc_time;
	u8 alarm1_time[NR_RTC_CNT_REGS];	
#endif
	mutex_lock(&info->lock);
	
	ret = s2m_rtc_update(info, S2M_RTC_READ);
	if (ret < 0)
		dev_err(info->dev, "%s: fail to update RTC(%d)\n", __func__,ret);

	ret = sec_rtc_bulk_read(info->iodev, S2M_RTC_SEC, NR_RTC_CNT_REGS, data);
	if (ret < 0) 
		dev_err(info->dev, "%s: fail to read time reg(%d)\n", __func__,ret);
	

	dev_info(info->dev, "%s: %d-%02d-%02d %02d:%02d:%02d(0x%02x)%s\n",
			__func__, data[RTC_YEAR] + 2000, data[RTC_MONTH],
			data[RTC_DATE], data[RTC_HOUR] & 0x1f, data[RTC_MIN],
			data[RTC_SEC], data[RTC_WEEKDAY],
			data[RTC_HOUR] & HOUR_PM_MASK ? "PM" : "AM");


#if defined(CONFIG_RTC_ALARM_BOOT)

	ret = sec_rtc_bulk_read(info->iodev, S2M_ALARM1_SEC, 7, alarm1_time);
	if (ret < 0)
		dev_err(info->dev, "%s: fail to read time reg(%d)\n", __func__,ret);
	
	s2m_data_to_tm(alarm1_time, &temp_rtc_time);

	dev_info(info->dev, "%s: %d-%02d-%02d %02d:%02d:%02d(%d)\n", __func__,
		temp_rtc_time.tm_year + 1900, temp_rtc_time.tm_mon + 1,
		temp_rtc_time.tm_mday, temp_rtc_time.tm_hour,
		temp_rtc_time.tm_min, temp_rtc_time.tm_sec,
		temp_rtc_time.tm_wday);

	rtc_tm_to_time(&temp_rtc_time, &alarm_time);

	s2m_data_to_tm(data, &temp_rtc_time);

	dev_info(info->dev, "%s: %d-%02d-%02d %02d:%02d:%02d(%d)\n", __func__,
			temp_rtc_time.tm_year + 1900, temp_rtc_time.tm_mon + 1,
			temp_rtc_time.tm_mday, temp_rtc_time.tm_hour,
			temp_rtc_time.tm_min, temp_rtc_time.tm_sec,
			temp_rtc_time.tm_wday);

	rtc_tm_to_time(&temp_rtc_time, &rtc_time);

	alarm_time = alarm_time / 60;
	rtc_time = rtc_time / 60;

	
	if (alarm_time > rtc_time && alarm_time < rtc_time +5) {	//if alarm_boot time is within 5min of current RTC
		pr_info("[SDCHG][%s]alarm within 5min\n", __func__);
		mutex_unlock(&info->lock);
		return 0;					//then do anything. System will boot by alarm_boot
	}

#endif

	rtc_balarm_min_for_dischg = data[RTC_MIN];
	rtc_balarm_min = rtc_balarm_min_for_dischg + RTC_BWAKEUP_AMIN;

	if(rtc_balarm_min >= RTC_BWAKEUP_ALOOP_MIN)
		rtc_balarm_min = rtc_balarm_min -RTC_BWAKEUP_ALOOP_MIN;

	s2m_rtc_stop_balarm_dischg(info);
	
	ret = sec_rtc_read(info->iodev, S2M_RTC_UPDATE, &rtcwake);

	if (ret < 0)
	{
		printk(KERN_ERR "%s: read fail \n", __func__);
		mutex_unlock(&info->lock);
		return ret;
	}
	
	printk(KERN_INFO "%s: rtcwake(before) = %d\n",__func__,rtcwake);

	rtcwake |= RTC_WAKE_MASK;
	
	printk(KERN_INFO "%s: rtcwake(after) = %d\n",__func__,rtcwake);	
	
	ret = sec_rtc_write(info->iodev, S2M_RTC_UPDATE, (char)rtcwake);

	if (ret < 0) {
		dev_err(info->dev, "%s: fail to write update reg(%d)\n",
				__func__, ret);
	} else {
		usleep_range(1000, 1000);
	}

	ret = sec_rtc_bulk_write(info->iodev, S2M_ALARM0_MIN, 1, &rtc_balarm_min);
	if (ret < 0){
		dev_err(info->dev, "%s: fail to write update reg(%d)\n",
				__func__, ret);
	}
	
	ret = s2m_rtc_update_reg_dischg(info, S2M_RTC_WRITE_ALARM);
	if (ret < 0)
		printk(KERN_ERR "%s: s2m_rtc_update_reg_dischg FAIL!!\n",__func__);
	else
		printk(KERN_INFO "%s: s2m_rtc_update_reg_dischg SUCCESS!!\n",__func__);

	ret = s2m_rtc_start_balarm_dischg(info);	
	if (ret < 0)
		printk(KERN_ERR "%s: s2m_rtc_start_balarm_dischg FAIL!!\n",__func__);
	else
		printk(KERN_INFO "%s: s2m_rtc_start_balarm_dischg SUCCESS!!\n",__func__);

	ret = sec_rtc_bulk_read(info->iodev, S2M_ALARM0_SEC, NR_RTC_CNT_REGS, data);
	if(ret < 0)
		printk(KERN_ERR "%s: RTC_MIN read fail\n",__func__);
	else
		printk(KERN_INFO "%s: RTC_MIN = %d\n",__func__,data[RTC_MIN]);

	info->dchg_check_rtc_set = true;
	mutex_unlock(&info->lock);
	
	return ret;
}
#endif

static int s2m_rtc_alarm_irq_enable(struct device *dev,
					unsigned int enabled)
{
	struct s2m_rtc_info *info = dev_get_drvdata(dev);
	int ret;

	mutex_lock(&info->lock);
	ret = s2m_rtc_set_alarm_enable(info, enabled);
	mutex_unlock(&info->lock);
	return ret;
}

static irqreturn_t s2m_rtc_alarm_irq(int irq, void *data)
{
	struct s2m_rtc_info *info = data;

	if (!info->rtc_dev)
		return IRQ_HANDLED;

	dev_info(info->dev, "%s:irq(%d)\n", __func__, irq);

	rtc_update_irq(info->rtc_dev, 1, RTC_IRQF | RTC_AF);
	__pm_wakeup_event(rtc_ws, 500);
	return IRQ_HANDLED;
}

#if defined(CONFIG_RTC_ALARM_BOOT)
static irqreturn_t s2m_rtc_alarm1_irq(int irq, void *data)
{
	struct s2m_rtc_info *info = data;

	dev_info(info->dev, "%s:irq(%d), lpm_mode:(%d)\n",
						__func__, irq, info->lpm_mode);

	if (info->lpm_mode) {
		wake_lock(&info->alarm_wake_lock);
		info->alarm_irq_flag = true;
	}

	rtc_update_irq(info->rtc_dev, 1, RTC_IRQF | RTC_AF);

	return IRQ_HANDLED;
}
#endif

static irqreturn_t s2m_smpl_warn_irq(int irq, void *data)
{
	struct s2m_rtc_info *info = data;

	if (!info->rtc_dev)
		return IRQ_HANDLED;

	dev_info(info->dev, "%s:irq(%d)\n", __func__, irq);

	schedule_work(&info->irq_work);

	return IRQ_HANDLED;
}

static void exynos_smpl_warn_work(struct work_struct *work)
{
	struct s2m_rtc_info *info = container_of(work,
			struct s2m_rtc_info, irq_work);
	int state = 0;

	do {
		state = (gpio_get_value(info->smpl_warn_info) & 0x1);
		msleep(100);
	} while (state);

	exynos_cpufreq_smpl_warn_notify_call_chain();

}

static void s2m_adc_read_data(struct s2m_rtc_info *info)
{
	/* adc data read */
	sec_reg_write(info->iodev, S2MPS15_REG_ADC_CTRL2, 0x93);
	sec_bulk_read(info->iodev, S2MPS15_REG_ADC_DATA, S2MPS15_MAX_ADC_CHANNEL, info->adc_val);
}

static unsigned int get_coeff(struct device *dev, u8 adc_reg_num)
{
	struct s2m_rtc_info *info = dev_get_drvdata(dev);
	unsigned int coeff, temp;
	u8 is_evt2;

	if (SEC_PMIC_REV(info->iodev) == 0x0)
		is_evt2 = 0;
	else if (SEC_PMIC_REV(info->iodev) == 0x1) {
		sec_reg_read(info->iodev, 0x59, &temp);
		is_evt2 = ((temp & 0x10) == 0x10) ? 1 : 0;
	} else
		is_evt2 = 1;

	/* if the regulator is LDO */
	if (adc_reg_num >= S2MPS15_LDO_START && adc_reg_num <= S2MPS15_LDO_END)
		coeff = s2mps15_ldo_coeff;
	/* if the regulator is BUCK */
	else if (adc_reg_num >= S2MPS15_BUCK_START && adc_reg_num <= S2MPS15_BUCK_END)
		coeff = is_evt2 ? s2mps15_buck_coeffs[adc_reg_num - 1][1] : s2mps15_buck_coeffs[adc_reg_num - 1][0];
	else {
		dev_err(info->dev, "%s: invalid adc regulator number(%d)\n", __func__, adc_reg_num);
		coeff = 0;
	}

	return coeff;
}

static ssize_t adc_val_0_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct s2m_rtc_info *info = dev_get_drvdata(dev);
	s2m_adc_read_data(info);
	return snprintf(buf, PAGE_SIZE, "%d\n", info->adc_val[0] * get_coeff(dev, info->adc_reg[0]));
}

static ssize_t adc_val_1_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct s2m_rtc_info *info = dev_get_drvdata(dev);
	s2m_adc_read_data(info);
	return snprintf(buf, PAGE_SIZE, "%d\n", info->adc_val[1] * get_coeff(dev, info->adc_reg[1]));
}

static ssize_t adc_val_2_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct s2m_rtc_info *info = dev_get_drvdata(dev);
	s2m_adc_read_data(info);
	return snprintf(buf, PAGE_SIZE, "%d\n", info->adc_val[2] * get_coeff(dev, info->adc_reg[2]));
}

static ssize_t adc_val_3_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct s2m_rtc_info *info = dev_get_drvdata(dev);
	s2m_adc_read_data(info);
	return snprintf(buf, PAGE_SIZE, "%d\n", info->adc_val[3] * get_coeff(dev, info->adc_reg[3]));
}

static ssize_t adc_val_all_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct s2m_rtc_info *info = dev_get_drvdata(dev);
	s2m_adc_read_data(info);
	return snprintf(buf, PAGE_SIZE, "CH1[%x]:%d uA (%d), CH2[%x]:%d uA (%d), CH3[%x]:%d uA (%d), CH4[%x]:%d uA (%d)\n",
			info->adc_reg[0], info->adc_val[0] * get_coeff(dev, info->adc_reg[0]), info->adc_val[0],
			info->adc_reg[1], info->adc_val[1] * get_coeff(dev, info->adc_reg[1]), info->adc_val[1],
			info->adc_reg[2], info->adc_val[2] * get_coeff(dev, info->adc_reg[2]), info->adc_val[2],
			info->adc_reg[3], info->adc_val[3] * get_coeff(dev, info->adc_reg[3]), info->adc_val[3]);
}

static ssize_t adc_reg_0_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct s2m_rtc_info *info = dev_get_drvdata(dev);
	return snprintf(buf, PAGE_SIZE, "%x\n", info->adc_reg[0]);
}

static ssize_t adc_reg_1_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct s2m_rtc_info *info = dev_get_drvdata(dev);
	return snprintf(buf, PAGE_SIZE, "%x\n", info->adc_reg[1]);
}

static ssize_t adc_reg_2_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct s2m_rtc_info *info = dev_get_drvdata(dev);
	return snprintf(buf, PAGE_SIZE, "%x\n", info->adc_reg[2]);
}

static ssize_t adc_reg_3_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct s2m_rtc_info *info = dev_get_drvdata(dev);
	return snprintf(buf, PAGE_SIZE, "%x\n", info->adc_reg[3]);
}

static ssize_t adc_ctrl2_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct s2m_rtc_info *info = dev_get_drvdata(dev);
	u8 adc_ctrl2;

	sec_reg_read(info->iodev, S2MPS15_REG_ADC_CTRL2, &adc_ctrl2);
	return snprintf(buf, PAGE_SIZE, "%x\n", adc_ctrl2);
}

static u8 buf_to_adc_reg(const char *buf)
{
	u8 adc_reg_num;

	if (kstrtou8(buf, 16, &adc_reg_num))
		return 0;

	if ((adc_reg_num >= S2MPS15_BUCK_START && adc_reg_num <= S2MPS15_BUCK_END) ||
			(adc_reg_num >= S2MPS15_LDO_START && adc_reg_num <= S2MPS15_LDO_END))
		return adc_reg_num;
	else
		return 0;
}

static void adc_reg_update(struct device *dev)
{
	struct s2m_rtc_info *info = dev_get_drvdata(dev);

	/* ADC temporarily off */
	sec_reg_write(info->iodev, S2MPS15_REG_ADC_CTRL2, 0);

	/* mux program enable, auto increase enable */
	sec_reg_write(info->iodev, S2MPS15_REG_ADC_CTRL2, 0x14);
	sec_bulk_write(info->iodev, S2MPS15_REG_ADC_DATA, S2MPS15_MAX_ADC_CHANNEL, info->adc_reg);

	/* ADC Continuous ON */
	sec_reg_write(info->iodev, S2MPS15_REG_ADC_CTRL2, S2MPS15_ADCEN_MASK);
}

static void adc_ctrl1_update(struct device *dev)
{
	struct s2m_rtc_info *info = dev_get_drvdata(dev);

	/* ADC temporarily off */
	sec_reg_write(info->iodev, S2MPS15_REG_ADC_CTRL2, 0);

	/* update ADC_CTRL1 register */
	sec_reg_write(info->iodev, S2MPS15_REG_ADC_CTRL1, info->adc_ctrl1);

	/* ADC Continuous ON */
	sec_reg_write(info->iodev, S2MPS15_REG_ADC_CTRL2, S2MPS15_ADCEN_MASK);
}

static ssize_t adc_reg_0_store(struct device *dev, struct device_attribute *attr,
				const char *buf, size_t count)
{
	struct s2m_rtc_info *info = dev_get_drvdata(dev);
	u8 adc_reg_num = buf_to_adc_reg(buf);
	if (!adc_reg_num)
		return -EINVAL;
	else {
		info->adc_reg[0] = adc_reg_num;
		adc_reg_update(dev);
		return count;
	}
}

static ssize_t adc_reg_1_store(struct device *dev, struct device_attribute *attr,
				const char *buf, size_t count)
{
	struct s2m_rtc_info *info = dev_get_drvdata(dev);
	u8 adc_reg_num = buf_to_adc_reg(buf);
	if (!adc_reg_num)
		return -EINVAL;
	else {
		info->adc_reg[1] = adc_reg_num;
		adc_reg_update(dev);
		return count;
	}
}

static ssize_t adc_reg_2_store(struct device *dev, struct device_attribute *attr,
				const char *buf, size_t count)
{
	struct s2m_rtc_info *info = dev_get_drvdata(dev);
	u8 adc_reg_num = buf_to_adc_reg(buf);
	if (!adc_reg_num)
		return -EINVAL;
	else {
		info->adc_reg[2] = adc_reg_num;
		adc_reg_update(dev);
		return count;
	}
}

static ssize_t adc_reg_3_store(struct device *dev, struct device_attribute *attr,
				const char *buf, size_t count)
{
	struct s2m_rtc_info *info = dev_get_drvdata(dev);
	u8 adc_reg_num = buf_to_adc_reg(buf);
	if (!adc_reg_num)
		return -EINVAL;
	else {
		info->adc_reg[3] = adc_reg_num;
		adc_reg_update(dev);
		return count;
	}
}

static ssize_t adc_ctrl1_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct s2m_rtc_info *info = dev_get_drvdata(dev);
	return snprintf(buf, PAGE_SIZE, "%x\n", info->adc_ctrl1);
}

static ssize_t adc_ctrl1_store(struct device *dev, struct device_attribute *attr,
				const char *buf, size_t count)
{
	struct s2m_rtc_info *info = dev_get_drvdata(dev);
	int ret;
	u8 temp;

	ret = kstrtou8(buf, 16, &temp);
	if (ret)
		return -EINVAL;
	else {
		info->adc_ctrl1 = temp & 0x3f;
		adc_ctrl1_update(dev);
		return count;
	}
}

static DEVICE_ATTR(adc_val_0, 0444, adc_val_0_show, NULL);
static DEVICE_ATTR(adc_val_1, 0444, adc_val_1_show, NULL);
static DEVICE_ATTR(adc_val_2, 0444, adc_val_2_show, NULL);
static DEVICE_ATTR(adc_val_3, 0444, adc_val_3_show, NULL);
static DEVICE_ATTR(adc_val_all, 0444, adc_val_all_show, NULL);
static DEVICE_ATTR(adc_ctrl2, 0444, adc_ctrl2_show, NULL);
static DEVICE_ATTR(adc_reg_0, 0644, adc_reg_0_show, adc_reg_0_store);
static DEVICE_ATTR(adc_reg_1, 0644, adc_reg_1_show, adc_reg_1_store);
static DEVICE_ATTR(adc_reg_2, 0644, adc_reg_2_show, adc_reg_2_store);
static DEVICE_ATTR(adc_reg_3, 0644, adc_reg_3_show, adc_reg_3_store);
static DEVICE_ATTR(adc_ctrl1, 0644, adc_ctrl1_show, adc_ctrl1_store);

static void adc_init(struct s2m_rtc_info *info)
{
	int ret;
	switch (info->iodev->device_type) {
	case S2MPS15X:
		info->adc_val = kzalloc(sizeof(u8)*S2MPS15_MAX_ADC_CHANNEL, GFP_KERNEL);
		info->adc_reg = kzalloc(sizeof(u8)*S2MPS15_MAX_ADC_CHANNEL, GFP_KERNEL);
		/* initial regulators : BUCK 2,3,6,1 */
		info->adc_reg[0] = 0x2;
		info->adc_reg[1] = 0x3;
		info->adc_reg[2] = 0x6;
		info->adc_reg[3] = 0x1;
		/* sample number : 32, divide ratio : (15+1)*2 = 32
		ADC clock = 500KHz/32 = 15.625KHz, clock period per sample = 16 cycles,
		period of register update = (16/15.625) * 32 samples * 4 channels = 131.072ms  */
		info->adc_ctrl1 = 0x2f;
		sec_reg_write(info->iodev, S2MPS15_REG_ADC_CTRL1, 0x2F);
		/* mux program enable, auto increase enable */
		sec_reg_write(info->iodev, S2MPS15_REG_ADC_CTRL2, 0x14);
		sec_bulk_write(info->iodev, S2MPS15_REG_ADC_DATA, S2MPS15_MAX_ADC_CHANNEL, info->adc_reg);
		/* ADC Continuous ON */
		sec_reg_write(info->iodev, S2MPS15_REG_ADC_CTRL2, S2MPS15_ADCEN_MASK);
		/* create sysfs entries */
		ret = device_create_file(info->dev, &dev_attr_adc_val_0);
		if (ret)
			goto err_adc_val_0;
		ret = device_create_file(info->dev, &dev_attr_adc_val_1);
		if (ret)
			goto remove_adc_val_0;
		ret = device_create_file(info->dev, &dev_attr_adc_val_2);
		if (ret)
			goto remove_adc_val_1;
		ret = device_create_file(info->dev, &dev_attr_adc_val_3);
		if (ret)
			goto remove_adc_val_2;
		ret = device_create_file(info->dev, &dev_attr_adc_ctrl2);
		if (ret)
			goto remove_adc_val_3;
		ret = device_create_file(info->dev, &dev_attr_adc_val_all);
		if (ret)
			goto remove_adc_ctrl2;
		ret = device_create_file(info->dev, &dev_attr_adc_reg_0);
		if (ret)
			goto remove_adc_val_all;
		ret = device_create_file(info->dev, &dev_attr_adc_reg_1);
		if (ret)
			goto remove_adc_reg_0;
		ret = device_create_file(info->dev, &dev_attr_adc_reg_2);
		if (ret)
			goto remove_adc_reg_1;
		ret = device_create_file(info->dev, &dev_attr_adc_reg_3);
		if (ret)
			goto remove_adc_reg_2;
		ret = device_create_file(info->dev, &dev_attr_adc_ctrl1);
		if (ret)
			goto remove_adc_reg_3;
		break;
	default:
		break;
	}
	return ;

remove_adc_reg_3:
	device_remove_file(info->dev, &dev_attr_adc_reg_3);
remove_adc_reg_2:
	device_remove_file(info->dev, &dev_attr_adc_reg_2);
remove_adc_reg_1:
	device_remove_file(info->dev, &dev_attr_adc_reg_1);
remove_adc_reg_0:
	device_remove_file(info->dev, &dev_attr_adc_reg_0);
remove_adc_val_all:
	device_remove_file(info->dev, &dev_attr_adc_val_all);
remove_adc_ctrl2:
	device_remove_file(info->dev, &dev_attr_adc_ctrl2);
remove_adc_val_3:
	device_remove_file(info->dev, &dev_attr_adc_val_3);
remove_adc_val_2:
	device_remove_file(info->dev, &dev_attr_adc_val_2);
remove_adc_val_1:
	device_remove_file(info->dev, &dev_attr_adc_val_1);
remove_adc_val_0:
	device_remove_file(info->dev, &dev_attr_adc_val_0);
err_adc_val_0:
	return ;
}

static void adc_deinit(struct s2m_rtc_info *info)
{
	switch (info->iodev->device_type) {
	case S2MPS15X:
		/* remove sysfs entries */
		device_remove_file(info->dev, &dev_attr_adc_val_0);
		device_remove_file(info->dev, &dev_attr_adc_val_1);
		device_remove_file(info->dev, &dev_attr_adc_val_2);
		device_remove_file(info->dev, &dev_attr_adc_val_3);
		device_remove_file(info->dev, &dev_attr_adc_ctrl2);
		device_remove_file(info->dev, &dev_attr_adc_val_all);
		device_remove_file(info->dev, &dev_attr_adc_reg_0);
		device_remove_file(info->dev, &dev_attr_adc_reg_1);
		device_remove_file(info->dev, &dev_attr_adc_reg_2);
		device_remove_file(info->dev, &dev_attr_adc_reg_3);
		device_remove_file(info->dev, &dev_attr_adc_ctrl1);
		/* ADC turned off */
		sec_reg_write(info->iodev, S2MPS15_REG_ADC_CTRL2, 0);
		kfree(info->adc_val);
		kfree(info->adc_reg);
		break;
	default:
		break;
	}
}

static const struct rtc_class_ops s2m_rtc_ops = {
	.read_time = s2m_rtc_read_time,
	.set_time = s2m_rtc_set_time,
	.read_alarm = s2m_rtc_read_alarm,
	.set_alarm = s2m_rtc_set_alarm,
#if defined(CONFIG_RTC_ALARM_BOOT)
	.set_alarm_boot = s2m_rtc_set_alarm_boot,
	.get_alarm_boot = s2m_rtc_get_alarm_boot,
#endif
	.alarm_irq_enable = s2m_rtc_alarm_irq_enable,
};

static bool s2m_is_jigonb_low(struct s2m_rtc_info *info)
{
	int ret, reg;
	u32 val, mask;

	switch (info->iodev->device_type) {
	case S2MPS11X:
		reg = S2MPS11_REG_ST1;
		mask = BIT(1);
		break;
	case S2MPS13X:
		reg = S2MPS13_REG_ST1;
		mask = BIT(1);
		break;
	case S2MPS15X:
		reg = S2MPS15_REG_ST1;
		mask = BIT(1);
		break;
	case S2MPU03X:
		reg = S2MPU03_REG_ST1;
		mask = BIT(1);
		break;
	default:
		/* If this happens the core funtion has a problem */
		BUG();
	}

	ret = sec_reg_read(info->iodev, reg, &val);
	if (ret < 0) {
		dev_err(info->dev, "%s: fail to read status1 reg(%d)\n",
			__func__, ret);
		return false;
	}

	return !(val & mask);
}

static void s2m_rtc_enable_wtsr_smpl(struct s2m_rtc_info *info,
						struct sec_platform_data *pdata)
{
	u8 val;
	int ret;

	if (pdata->wtsr_smpl->check_jigon && s2m_is_jigonb_low(info))
		pdata->wtsr_smpl->smpl_en = false;

#ifdef CONFIG_SEC_FACTORY
	/* FIXME: Must check board revision!!! */
	pdata->wtsr_smpl->smpl_en = false;
#endif

	val = (pdata->wtsr_smpl->wtsr_en << WTSR_EN_SHIFT)
		| (pdata->wtsr_smpl->smpl_en << SMPL_EN_SHIFT)
		| WTSR_TIMER_BITS(pdata->wtsr_smpl->wtsr_timer_val)
		| SMPL_TIMER_BITS(pdata->wtsr_smpl->smpl_timer_val);

	dev_info(info->dev, "%s: WTSR: %s, SMPL: %s\n", __func__,
			pdata->wtsr_smpl->wtsr_en ? "enable" : "disable",
			pdata->wtsr_smpl->smpl_en ? "enable" : "disable");

	ret = sec_rtc_write(info->iodev, S2M_RTC_WTSR_SMPL, val);
	if (ret < 0) {
		dev_err(info->dev, "%s: fail to write WTSR/SMPL reg(%d)\n",
				__func__, ret);
		return;
	}
	info->wtsr_en = pdata->wtsr_smpl->wtsr_en;
	info->smpl_en = pdata->wtsr_smpl->smpl_en;
}

static void s2m_rtc_disable_wtsr_smpl(struct s2m_rtc_info *info,
					struct sec_platform_data *pdata)
{
	int ret;

	dev_info(info->dev, "%s: disable WTSR\n", __func__);
	ret = sec_rtc_update(info->iodev, S2M_RTC_WTSR_SMPL, 0,
			WTSR_EN_MASK | SMPL_EN_MASK);
	if (ret < 0)
		dev_err(info->dev, "%s: fail to update WTSR reg(%d)\n",
				__func__, ret);
}

static int s2m_rtc_init_reg(struct s2m_rtc_info *info,
				struct sec_platform_data *pdata)
{
	u32 data, update_val, ctrl_val, capsel_val;
	int ret;

#if defined(CONFIG_RTC_ALARM_BOOT)
	u8 data_alm1[7];
	struct rtc_time alrm;

	ret = sec_rtc_bulk_read(info->iodev, S2M_ALARM1_SEC, 7, data_alm1);
	if (ret < 0)
		return ret;

	s2m_data_to_tm(data_alm1, &alrm);

	printk(KERN_INFO "%s: %d/%d/%d %d:%d:%d(%d)\n", __func__,
		1900 + alrm.tm_year, 1 + alrm.tm_mon,
		alrm.tm_mday, alrm.tm_hour,
		alrm.tm_min, alrm.tm_sec,
		alrm.tm_wday);
#endif

	ret = sec_rtc_read(info->iodev, S2M_RTC_UPDATE, &update_val);
	if (ret < 0) {
		dev_err(info->dev, "%s: fail to read update reg(%d)\n",
			__func__, ret);
		return ret;
	}

	info->update_reg =
		update_val & ~(info->wudr_mask | RTC_FREEZE_MASK | RTC_RUDR_MASK | info->audr_mask);

	ret = sec_rtc_write(info->iodev, S2M_RTC_UPDATE, info->update_reg);
	if (ret < 0) {
		dev_err(info->dev, "%s: fail to write update reg(%d)\n",
			__func__, ret);
		return ret;
	}

	s2m_rtc_update(info, S2M_RTC_READ);

	ret = sec_rtc_read(info->iodev, S2M_RTC_CTRL, &ctrl_val);
	if (ret < 0) {
		dev_err(info->dev, "%s: fail to read control reg(%d)\n",
			__func__, ret);
		return ret;
	}

	ret = sec_rtc_read(info->iodev, S2M_CAP_SEL, &capsel_val);
	if (ret < 0) {
		dev_err(info->dev, "%s: fail to read cap_sel reg(%d)\n",
			__func__, ret);
		return ret;
	}

	/* If the value of RTC_CTRL register is 0, RTC registers were reset */
	if ((ctrl_val & MODEL24_MASK) && (capsel_val == 0xf8))
		return 0;

	/* Set RTC control register : Binary mode, 24hour mode */
	data = MODEL24_MASK;
	ret = sec_rtc_write(info->iodev, S2M_RTC_CTRL, data);
	if (ret < 0) {
		dev_err(info->dev, "%s: fail to write CTRL reg(%d)\n",
			__func__, ret);
		return ret;
	}

	ret = s2m_rtc_update(info, S2M_RTC_WRITE_ALARM);
	if (ret < 0)
		return ret;

	ret = sec_rtc_write(info->iodev, S2M_CAP_SEL, 0xf8);
	if (ret < 0) {
		dev_err(info->dev, "%s: fail to write CAP_SEL reg(%d)\n",
				__func__, ret);
		return ret;
	}

	if (pdata->init_time) {
		dev_info(info->dev, "%s: initialize RTC time\n", __func__);
		ret = s2m_rtc_set_time(info->dev, pdata->init_time);
	}
	return ret;
}

static int s2m_rtc_probe(struct platform_device *pdev)
{
	struct sec_pmic_dev *iodev = dev_get_drvdata(pdev->dev.parent);
	struct sec_platform_data *pdata = dev_get_platdata(iodev->dev);
	struct s2m_rtc_info *info;
	int irq_base;
	int ret = 0;

	info = devm_kzalloc(&pdev->dev, sizeof(struct s2m_rtc_info),
				GFP_KERNEL);

	if (!info)
		return -ENOMEM;
#ifdef CONFIG_EXYNOS_MBOX
	irq_base = iodev->irq_base;
#else
	irq_base = regmap_irq_chip_get_base(iodev->irq_data);
#endif
	if (!irq_base) {
		dev_err(&pdev->dev, "Failed to get irq base %d\n", irq_base);
		return -ENODEV;
	}

	mutex_init(&info->lock);
	info->dev = &pdev->dev;
	info->iodev = iodev;
	info->alarm_check = false;
	info->udr_updated = false;
	info->use_alarm_workaround = false;
	info->wudr_mask = RTC_WUDR_MASK;
	info->audr_mask = RTC_AUDR_MASK;
#if 0 //#ifdef CONFIG_BATTERY_SWELLING_SELF_DISCHARGING
	info->dchg_check_rtc_set = false;
#endif

	switch (iodev->device_type) {
	case S2MPU03X:
		info->irq = irq_base + S2MPU03_IRQ_RTCA0;
		info->alarm_check = true;
		info->wudr_mask = RTC_WUDR_MASK_REV;
		info->audr_mask = RTC_AUDR_MASK_REV;
		break;
	case S2MPS15X:
		info->irq = irq_base + S2MPS15_IRQ_RTCA0;
#if defined(CONFIG_RTC_ALARM_BOOT)
		info->alarm_boot_irq = irq_base + S2MPS15_IRQ_RTCA1;
#endif
		info->alarm_check = true;
		if (SEC_PMIC_REV(iodev)) {
			info->wudr_mask = RTC_WUDR_MASK_REV;
			info->audr_mask = RTC_AUDR_MASK_REV;
		}
		if (SEC_PMIC_REV(iodev)) {
			if (pdata->smpl_warn_en) {
				if (!gpio_is_valid(pdata->smpl_warn)) {
					dev_err(&pdev->dev, "smpl_warn GPIO NOT VALID\n");
					goto err_smpl_warn;
				}
				info->smpl_irq = gpio_to_irq(pdata->smpl_warn);
				ret = devm_request_threaded_irq(&pdev->dev, info->smpl_irq,
					NULL, s2m_smpl_warn_irq, IRQF_TRIGGER_RISING | IRQF_ONESHOT,
					"SMPL WARN", info);
				if (ret < 0) {
					dev_err(&pdev->dev, "Failed to request smpl warn IRQ: %d: %d\n",
						info->smpl_irq, ret);
					goto err_smpl_warn;
				}
				info->smpl_warn_info = pdata->smpl_warn;
				INIT_WORK(&info->irq_work, exynos_smpl_warn_work);
				ret = sec_reg_update(info->iodev, S2MPS15_REG_ETC_TEST, 0x00, 0x10);
			} else {
				ret = sec_reg_update(info->iodev, S2MPS15_REG_ETC_TEST, 0x10, 0x10);
			}
			if (ret < 0) {
				dev_err(info->dev, "%s:%d fail to write smpl_warn_en(%d)\n",
					__func__, __LINE__, ret);
				goto err_smpl_warn;
			}
		}
		if (pdata->adc_en)
			adc_init(info);

		break;
	case S2MPS13X:
		info->irq = irq_base + S2MPS13_IRQ_RTCA0;
		if (SEC_PMIC_REV(iodev) > 0x02) {
			if (pdata->smpl_warn_en) {
				if (!gpio_is_valid(pdata->smpl_warn)) {
					dev_err(&pdev->dev, "smpl_warn GPIO NOT VALID\n");
					goto err_smpl_warn;
				}
				info->smpl_irq = gpio_to_irq(pdata->smpl_warn);
				ret = devm_request_threaded_irq(&pdev->dev, info->smpl_irq,
					NULL, s2m_smpl_warn_irq, IRQF_TRIGGER_RISING | IRQF_ONESHOT,
					"SMPL WARN", info);
				if (ret < 0) {
					dev_err(&pdev->dev, "Failed to request smpl warn IRQ: %d: %d\n",
						info->smpl_irq, ret);
					goto err_smpl_warn;
				}
				info->smpl_warn_info = pdata->smpl_warn;
				INIT_WORK(&info->irq_work, exynos_smpl_warn_work);
				ret = sec_reg_update(info->iodev, S2MPS13_REG_ETC_TEST, 0x00, 0x10);
			} else {
				ret = sec_reg_update(info->iodev, S2MPS13_REG_ETC_TEST, 0x10, 0x10);
			}
			if (ret < 0) {
				dev_err(info->dev, "%s:%d fail to write smpl_warn_en(%d)\n",
					__func__, __LINE__, ret);
				goto err_smpl_warn;
			}
			info->alarm_check = true;
			info->udr_updated = true;
		} else {
			info->use_alarm_workaround = true;
		}
		break;
	case S2MPS11X:
		info->irq = irq_base + S2MPS11_IRQ_RTCA0;
		break;
	default:
		/* If this happens the core funtion has a problem */
		BUG();
	}

	platform_set_drvdata(pdev, info);

	ret = s2m_rtc_init_reg(info, pdata);
	if (ret < 0) {
		dev_err(&pdev->dev, "Failed to initialize RTC reg:%d\n", ret);
		goto err_rtc_init_reg;
	}

	if (pdata->wtsr_smpl)
		s2m_rtc_enable_wtsr_smpl(info, pdata);

	device_init_wakeup(&pdev->dev, true);
	rtc_ws = wakeup_source_register("rtc-sec");

	ret = devm_request_threaded_irq(&pdev->dev, info->irq, NULL,
			s2m_rtc_alarm_irq, 0, "rtc-alarm0", info);
	if (ret < 0) {
		dev_err(&pdev->dev, "Failed to request alarm IRQ: %d: %d\n",
			info->irq, ret);
		goto err_rtc_irq;
	}
	disable_irq(info->irq);
	disable_irq(info->irq);
	info->use_irq = true;

	info->rtc_dev = devm_rtc_device_register(&pdev->dev, "s2m-rtc",
			&s2m_rtc_ops, THIS_MODULE);

	if (IS_ERR(info->rtc_dev)) {
		ret = PTR_ERR(info->rtc_dev);
		dev_err(&pdev->dev, "Failed to register RTC device: %d\n", ret);
		goto err_rtc_dev_register;
	}
	enable_irq(info->irq);

#if defined(CONFIG_RTC_ALARM_BOOT)
		ret = devm_request_threaded_irq(&pdev->dev, info->alarm_boot_irq, NULL,
			s2m_rtc_alarm1_irq, 0, "rtc-alarm1", info);

		if (ret < 0)
			dev_err(&pdev->dev, "Failed to request alarm IRQ: %d: %d\n",
				info->alarm_boot_irq, ret);

		info->lpm_mode = lpcharge;

		if(info->lpm_mode)
			wake_lock_init(&info->alarm_wake_lock, WAKE_LOCK_SUSPEND,
													"alarm_wake_lock");
#endif

	return 0;

err_rtc_dev_register:
	enable_irq(info->irq);
	enable_irq(info->irq);

err_rtc_irq:
	wakeup_source_unregister(rtc_ws);
err_rtc_init_reg:
	platform_set_drvdata(pdev, NULL);
err_smpl_warn:
	mutex_destroy(&info->lock);

	return ret;
}

static int s2m_rtc_remove(struct platform_device *pdev)
{
	struct s2m_rtc_info *info = platform_get_drvdata(pdev);
	struct sec_platform_data *pdata = dev_get_platdata(info->iodev->dev);

	if (!info->alarm_enabled)
		enable_irq(info->irq);

	if (pdata->adc_en)
		adc_deinit(info);

#if defined(CONFIG_RTC_ALARM_BOOT)
		free_irq(info->alarm_boot_irq, info);
#endif

	wakeup_source_unregister(rtc_ws);

	return 0;
}

static void s2m_rtc_shutdown(struct platform_device *pdev)
{
	struct s2m_rtc_info *info = platform_get_drvdata(pdev);
	struct sec_platform_data *pdata = dev_get_platdata(info->iodev->dev);

#if 0 //#ifdef CONFIG_BATTERY_SWELLING_SELF_DISCHARGING
	if(sdchg_nochip_support && (s2m_rtc_set_balarm_dischg_only(info) < 0))
		printk(KERN_ERR "%s: Failed to set alarm reg. for boot self-dischg\n \n",
				 __func__);
#endif

	if (info->wtsr_en || info->smpl_en)
		s2m_rtc_disable_wtsr_smpl(info, pdata);
}

static const struct platform_device_id s2m_rtc_id[] = {
	{ "s2m-rtc", 0 },
};

static struct platform_driver s2m_rtc_driver = {
	.driver		= {
		.name	= "s2m-rtc",
		.owner	= THIS_MODULE,
	},
	.probe		= s2m_rtc_probe,
	.remove		= s2m_rtc_remove,
	.shutdown	= s2m_rtc_shutdown,
	.id_table	= s2m_rtc_id,
};

module_platform_driver(s2m_rtc_driver);

/* Module information */
MODULE_AUTHOR("Sangbeom Kim <sbkim73@samsung.com>");
MODULE_DESCRIPTION("Samsung RTC driver");
MODULE_LICENSE("GPL");
