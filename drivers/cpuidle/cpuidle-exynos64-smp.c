/*
 * Copyright (c) 2014 Samsung Electronics Co., Ltd.
 *		http://www.samsung.com
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
*/

#include <linux/cpu.h>
#include <linux/cpuidle.h>
#include <linux/cpumask.h>
#include <linux/cpu_pm.h>
#include <linux/kernel.h>
#include <linux/of.h>
#include <linux/reboot.h>
#include <linux/suspend.h>

#include <asm/psci.h>
#include <asm/suspend.h>
#include <asm/tlbflush.h>

#include <mach/exynos-powermode-smp.h>

#include "of_idle_states.h"

enum idle_state {
	IDLE_C1 = 0,
	IDLE_C2,
	IDLE_CPD,
	IDLE_LPM,
};

/***************************************************************************
 *                             Helper function                             *
 ***************************************************************************/
static void prepare_idle(unsigned int cpuid)
{
	cpu_pm_enter();
}

static void post_idle(unsigned int cpuid)
{
	cpu_pm_exit();
}

static bool nonboot_cpus_working(void)
{
	return (num_online_cpus() > 1);
}

static bool idle_c2_disabled(struct cpuidle_driver *drv)
{
	return drv->states[IDLE_C2].disabled;
}

static int find_available_low_state(struct cpuidle_device *dev,
				struct cpuidle_driver *drv, unsigned int index)
{
	while (--index > 0) {
		struct cpuidle_state *s = &drv->states[index];
		struct cpuidle_state_usage *su = &dev->states_usage[index];

		if (s->disabled || su->disable)
			continue;
		else
			return index;
	}

	return IDLE_C1;
}

/***************************************************************************
 *                           Cpuidle state handler                         *
 ***************************************************************************/
static int exynos_enter_idle(struct cpuidle_device *dev,
				struct cpuidle_driver *drv, int index)
{
	cpuidle_profile_start_no_substate(dev->cpu, index);

	cpu_do_idle();

	cpuidle_profile_finish_no_earlywakeup(dev->cpu);

	return index;
}

static int exynos_enter_c2(struct cpuidle_device *dev,
				struct cpuidle_driver *drv, int index)
{
	int cpu = dev->cpu, ret, target_index;
	unsigned int target_residency = drv->states[index].target_residency;

	prepare_idle(dev->cpu);

	target_index = determine_cpd(index, IDLE_C2, cpu, target_residency);

	cpuidle_profile_start(dev->cpu, index, entry_index);

	ret = cpu_suspend(target_index);
	if (ret)
		flush_tlb_all();

	cpuidle_profile_finish(dev->cpu, ret);

	wakeup_from_c2(cpu);

	post_idle(dev->cpu);

	return target_index;
}

static int exynos_enter_lpm(struct cpuidle_device *dev,
				struct cpuidle_driver *drv, int index)
{
	int ret, mode;

	mode = determine_lpm();

	prepare_idle(dev->cpu);

	exynos_prepare_sys_powerdown(mode);

	cpuidle_profile_start(dev->cpu, index, mode);

	ret = cpu_suspend(index);

	cpuidle_profile_finish(dev->cpu, ret);

	exynos_wakeup_sys_powerdown(mode, (bool)ret);

	post_idle(dev->cpu);

	return index;
}

static int exynos_enter_idle_state(struct cpuidle_device *dev,
				struct cpuidle_driver *drv, int index)
{
	int (*func)(struct cpuidle_device *, struct cpuidle_driver *, int);
	ktime_t time_start, time_end;
	int ret;

	exynos_ss_cpuidle(index, 0, 0, ESS_FLAG_IN);
	time_start = ktime_get();

	switch (index) {
	case IDLE_C1:
		func = exynos_enter_idle;
		break;
	case IDLE_C2:
	case IDLE_CPD:
		func = idle_c2_disabled(drv) ? exynos_enter_idle
					     : exynos_enter_c2;
		break;
	case IDLE_LPM:
		/*
		 * In exynos, system can enter LPM when only boot core is running.
		 * In other words, non-boot cores should be shutdown to enter LPM.
		 */
		if (nonboot_cpus_working()) {
			index = find_available_low_state(dev, drv, index);
			return exynos_enter_idle_state(dev, drv, index);
		} else {
			func = exynos_enter_lpm;
		}
		break;
	default:
		pr_err("%s : Invalid index: %d\n", __func__, index);
		return -EINVAL;
	}

	ret = (*func)(dev, drv, index);

	time_end = ktime_get();
	exynos_ss_cpuidle(index, entered_state,
		(int)ktime_to_us(ktime_sub(time_end, time_start)), ESS_FLAG_OUT);

	return ret;
}

static int exynos_cpuidle_pm_notifier(struct notifier_block *nb,
				      unsigned long event, void *unused)
{
	switch (event) {
	case PM_SUSPEND_PREPARE:
		cpu_idle_poll_ctrl(true);
		return NOTIFY_OK;
	case PM_POST_SUSPEND:
	case PM_POST_RESTORE:
		cpu_idle_poll_ctrl(false);
		return NOTIFY_OK;
	}

	return NOTIFY_DONE;
}

static struct notifier_block exynos_cpuidle_pm_nb = {
	.notifier_call = exynos_cpuidle_pm_notifier,
};

/***************************************************************************
 *                            Define notifier call                         *
 ***************************************************************************/
static int exynos_cpuidle_reboot_notifier(struct notifier_block *this,
				unsigned long event, void *_cmd)
{
	switch (event) {
	case SYS_RESTART:
	case SYSTEM_POWER_OFF:
		cpu_idle_poll_ctrl(true);
		break;
	}

	return NOTIFY_OK;
}

static struct notifier_block exynos_cpuidle_reboot_nb = {
	.notifier_call = exynos_cpuidle_reboot_notifier,
};

typedef int (*suspend_init_fn)(struct cpuidle_driver *,
			       struct device_node *[]);

struct cpu_suspend_ops {
	const char *id;
	suspend_init_fn init_fn;
};

static const struct cpu_suspend_ops suspend_operations[] __initconst = {
	{"arm,psci", psci_dt_register_idle_states},
	{}
};

static __init const struct cpu_suspend_ops *get_suspend_ops(const char *str)
{
	int i;

	if (!str)
		return NULL;

	for (i = 0; suspend_operations[i].id; i++)
		if (!strcmp(suspend_operations[i].id, str))
			return &suspend_operations[i];

	return NULL;
}

static DEFINE_PER_CPU(struct cpuidle_device, exynos64_cpuidle_device);

static struct cpuidle_driver exynos64_idle_driver = {
	.name  = "exynos64_idle",
	.owner = THIS_MODULE,
};

static struct device_node *state_nodes[CPUIDLE_STATE_MAX] __initdata;

static int __init exynos_idle_state_init(struct cpuidle_driver *idle_drv,
					 const struct cpumask *mask)
{
	int i, ret;
	const char *entry_method;
	struct device_node *idle_states_node;
	const struct cpu_suspend_ops *suspend_init;
	struct cpuidle_driver *drv = idle_drv;

	idle_states_node = of_find_node_by_path("/cpus/idle-states");
	if (!idle_states_node)
		return -ENOENT;

	if (of_property_read_string(idle_states_node, "entry-method",
				    &entry_method)) {
		pr_warn(" * %s missing entry-method property\n",
			    idle_states_node->full_name);
		of_node_put(idle_states_node);
		return -EOPNOTSUPP;
	}

	suspend_init = get_suspend_ops(entry_method);
	if (!suspend_init) {
		pr_warn("Missing suspend initializer\n");
		of_node_put(idle_states_node);
		return -EOPNOTSUPP;
	}

	drv->cpumask = (struct cpumask *)mask;

	ret = of_init_idle_driver(drv, state_nodes, 0, true);
	if (ret)
		return ret;

	if (suspend_init->init_fn(drv, state_nodes))
		return -EOPNOTSUPP;

	for (i = 0; i < drv->state_count; i++)
		drv->states[i].enter = exynos_enter_idle_state;

	return 0;
}

static int __init exynos64_init_cpuidle(void)
{
	int cpu, ret;
	struct cpuidle_device *device;

	ret = exynos_idle_state_init(&exynos64_idle_driver, cpu_online_mask);
	if (ret)
		return ret;

	exynos64_idle_driver.safe_state_index = IDLE_C1;

	ret = cpuidle_register_driver(&exynos64_idle_driver);
	if (ret) {
		pr_err("cpuidle driver registeration failed\n");
		return ret;
	}

	for_each_cpu(cpu, cpu_online_mask) {
		device = &per_cpu(exynos64_cpuidle_device, cpu);
		device->cpu = cpu;

		device->state_count = exynos64_idle_driver.state_count;

		/* Non-boot cluster will skip idle time correlation */
		if (cpu & 0x4)
			device->skip_idle_correlation = true;
		else
			device->skip_idle_correlation = false;

		ret = cpuidle_register_device(device);
		if (ret) {
			pr_err("cpuidle device registeration failed\n");
			return ret;
		}
	}

	register_pm_notifier(&exynos_cpuidle_pm_nb);
	register_reboot_notifier(&exynos_cpuidle_reboot_nb);

	return 0;
}
device_initcall(exynos64_init_cpuidle);
