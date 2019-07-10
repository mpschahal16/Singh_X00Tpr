/* drivers/misc/lowmemorykiller.c
 *
 * The lowmemorykiller driver lets user-space specify a set of memory thresholds
 * where processes with a range of oom_score_adj values will get killed. Specify
 * the minimum oom_score_adj values in
 * /sys/module/lowmemorykiller/parameters/adj and the number of free pages in
 * /sys/module/lowmemorykiller/parameters/minfree. Both files take a comma
 * separated list of numbers in ascending order.
 *
 * For example, write "0,8" to /sys/module/lowmemorykiller/parameters/adj and
 * "1024,4096" to /sys/module/lowmemorykiller/parameters/minfree to kill
 * processes with a oom_score_adj value of 8 or higher when the free memory
 * drops below 4096 pages and kill processes with a oom_score_adj value of 0 or
 * higher when the free memory drops below 1024 pages.
 *
 * The driver considers memory used for caches to be free, but if a large
 * percentage of the cached memory is locked this can be very inaccurate
 * and processes may not get killed until the normal oom killer is triggered.
 *
 * Copyright (C) 2007-2008 Google, Inc.
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/init.h>
#include <linux/moduleparam.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/oom.h>
#include <linux/sched.h>
#include <linux/swap.h>
#include <linux/rcupdate.h>
#include <linux/profile.h>
#include <linux/notifier.h>
#include <linux/mutex.h>
#include <linux/delay.h>
#include <linux/swap.h>
#include <linux/fs.h>
#include <linux/cpuset.h>
#include <linux/vmpressure.h>
#include <linux/freezer.h>
#include <linux/zcache.h>

#define CREATE_TRACE_POINTS
#include <trace/events/almk.h>

#ifdef CONFIG_HIGHMEM
#define _ZONE ZONE_HIGHMEM
#else
#define _ZONE ZONE_NORMAL
#endif
#include <linux/circ_buf.h>
#include <linux/proc_fs.h>
#include <linux/slab.h>

#define CREATE_TRACE_POINTS
#include "trace/lowmemorykiller.h"

extern int extra_free_kbytes;

static uint32_t lowmem_debug_level = 0;
static short lowmem_adj[6] = {
	0,
	1,
	6,
	12,
};
static int lowmem_adj_size = 4;
static int lowmem_minfree[6] = {
	3 * 512,	/* 6MB */
	2 * 1024,	/* 8MB */
	4 * 1024,	/* 16MB */
	16 * 1024,	/* 64MB */
};
static int lowmem_minfree_size = 4;

static unsigned long lowmem_deathpending_timeout;

#define lowmem_print(level, x...)			\
	do {						\
		if (lowmem_debug_level >= (level))	\
			pr_info(x);			\
	} while (0)


/* User knob to enable/disable adaptive lmk feature */
static int enable_adaptive_lmk;
module_param_named(enable_adaptive_lmk, enable_adaptive_lmk, int,
		   S_IRUGO | S_IWUSR);

/*
 * This parameter controls the behaviour of LMK when vmpressure is in
 * the range of 90-94. Adaptive lmk triggers based on number of file
 * pages wrt vmpressure_file_min, when vmpressure is in the range of
 * 90-94. Usually this is a pseudo minfree value, higher than the
 * highest configured value in minfree array.
 */
static int vmpressure_file_min;
module_param_named(vmpressure_file_min, vmpressure_file_min, int,
		   S_IRUGO | S_IWUSR);

/* User knob to enable/disable oom reaping feature */
static int oom_reaper = 1;
module_param_named(oom_reaper, oom_reaper, int, 0644);

enum {
	VMPRESSURE_NO_ADJUST = 0,
	VMPRESSURE_ADJUST_ENCROACH,
	VMPRESSURE_ADJUST_NORMAL,
};

void handle_lmk_event(struct task_struct *selected, short min_score_adj)
{
	int head;
	int tail;
	struct lmk_event *events;
	struct lmk_event *event;
	int res;
	long rss_in_pages = -1;
	struct mm_struct *mm = get_task_mm(selected);

	if (mm) {
		rss_in_pages = get_mm_rss(mm);
		mmput(mm);
	}

	spin_lock(&lmk_event_lock);

	head = event_buffer.head;
	tail = READ_ONCE(event_buffer.tail);

	/* Do not continue to log if no space remains in the buffer. */
	if (CIRC_SPACE(head, tail, MAX_BUFFERED_EVENTS) < 1) {
		spin_unlock(&lmk_event_lock);
		return;
	}

	events = (struct lmk_event *) event_buffer.buf;
	event = &events[head];

	res = get_cmdline(selected, event->taskname, MAX_TASKNAME - 1);

	if (pressure >= 95) {
		other_file = global_page_state(NR_FILE_PAGES) + zcache_pages() -
			global_page_state(NR_SHMEM) -
			total_swapcache_pages();
		other_free = global_page_state(NR_FREE_PAGES);

		atomic_set(&shift_adj, 1);
//		trace_almk_vmpressure(pressure, other_free, other_file);
	} else if (pressure >= 90) {
		if (lowmem_adj_size < array_size)
			array_size = lowmem_adj_size;
		if (lowmem_minfree_size < array_size)
			array_size = lowmem_minfree_size;

		other_file = global_page_state(NR_FILE_PAGES) + zcache_pages() -
			global_page_state(NR_SHMEM) -
			total_swapcache_pages();

		other_free = global_page_state(NR_FREE_PAGES);

		if ((other_free < lowmem_minfree[array_size - 1]) &&
		    (other_file < vmpressure_file_min)) {
			atomic_set(&shift_adj, 1);
//			trace_almk_vmpressure(pressure, other_free, other_file);
		}
	} else if (atomic_read(&shift_adj)) {
		other_file = global_page_state(NR_FILE_PAGES) + zcache_pages() -
			global_page_state(NR_SHMEM) -
			total_swapcache_pages();
		other_free = global_page_state(NR_FREE_PAGES);

		/*
		 * shift_adj would have been set by a previous invocation
		 * of notifier, which is not followed by a lowmem_shrink yet.
		 * Since vmpressure has improved, reset shift_adj to avoid
		 * false adaptive LMK trigger.
		 */
//		trace_almk_vmpressure(pressure, other_free, other_file);
		atomic_set(&shift_adj, 0);
	}

	event->taskname[res] = '\0';
	event->pid = selected->pid;
	event->uid = from_kuid_munged(current_user_ns(), task_uid(selected));
	if (selected->group_leader)
		event->group_leader_pid = selected->group_leader->pid;
	else
		event->group_leader_pid = -1;
	event->min_flt = selected->min_flt;
	event->maj_flt = selected->maj_flt;
	event->oom_score_adj = selected->signal->oom_score_adj;
	event->start_time = nsec_to_clock_t(selected->real_start_time);
	event->rss_in_pages = rss_in_pages;
	event->min_score_adj = min_score_adj;

	event_buffer.head = (head + 1) & (MAX_BUFFERED_EVENTS - 1);

	spin_unlock(&lmk_event_lock);

	wake_up_interruptible(&event_wait);
}

static int lmk_event_show(struct seq_file *s, void *unused)
{
	struct lmk_event *events = (struct lmk_event *) event_buffer.buf;
	int head;
	int tail;
	struct lmk_event *event;

	spin_lock(&lmk_event_lock);

	head = event_buffer.head;
	tail = event_buffer.tail;

	if (head == tail) {
		spin_unlock(&lmk_event_lock);
		return -EAGAIN;
	}

	event = &events[tail];

	seq_printf(s, "%lu %lu %lu %lu %lu %lu %hd %hd %llu\n%s\n",
		(unsigned long) event->pid, (unsigned long) event->uid,
		(unsigned long) event->group_leader_pid, event->min_flt,
		event->maj_flt, event->rss_in_pages, event->oom_score_adj,
		event->min_score_adj, event->start_time, event->taskname);

	event_buffer.tail = (tail + 1) & (MAX_BUFFERED_EVENTS - 1);

	spin_unlock(&lmk_event_lock);
	return 0;
}

static unsigned int lmk_event_poll(struct file *file, poll_table *wait)
{
	int ret = 0;

	poll_wait(file, &event_wait, wait);
	spin_lock(&lmk_event_lock);
	if (event_buffer.head != event_buffer.tail)
		ret = POLLIN;
	spin_unlock(&lmk_event_lock);
	return ret;
}

static int lmk_event_open(struct inode *inode, struct file *file)
{
	return single_open(file, lmk_event_show, inode->i_private);
}

static const struct file_operations event_file_ops = {
	.open = lmk_event_open,
	.poll = lmk_event_poll,
	.read = seq_read
};

static void lmk_event_init(void)
{
	struct proc_dir_entry *entry;

	event_buffer.head = 0;
	event_buffer.tail = 0;
	event_buffer.buf = kmalloc(
		sizeof(struct lmk_event) * MAX_BUFFERED_EVENTS, GFP_KERNEL);
	if (!event_buffer.buf)
		return;
	entry = proc_create("lowmemorykiller", 0, NULL, &event_file_ops);
	if (!entry)
		pr_err("error creating kernel lmk event file\n");
}

static unsigned long lowmem_count(struct shrinker *s,
				  struct shrink_control *sc)
{
	return global_page_state(NR_ACTIVE_ANON) +
		global_page_state(NR_ACTIVE_FILE) +
		global_page_state(NR_INACTIVE_ANON) +
		global_page_state(NR_INACTIVE_FILE);
}

static void mark_lmk_victim(struct task_struct *tsk)
{
	struct mm_struct *mm = tsk->mm;

	if (!cmpxchg(&tsk->signal->oom_mm, NULL, mm)) {
		atomic_inc(&tsk->signal->oom_mm->mm_count);
		set_bit(MMF_OOM_VICTIM, &mm->flags);
	}
}

static int test_task_lmk_waiting(struct task_struct *p)
{
	struct task_struct *t = p;
 	do {
		task_lock(t);
		if (task_lmk_waiting(t)) {
			task_unlock(t);
			return 1;
		}
		task_unlock(t);
	} while_each_thread(p, t);
 	return 0;
}

static bool lowmem_whitelist(char *name)
{
	bool ret = false;
	if (name == NULL)return ret;

	if ((!strcmp(name, "com.miui.home")) ||
		(!strcmp(name, "com.android.launcher3")) ||
		(!strcmp(name, "com.android.quickstep")) ||
		(!strcmp(name, "org.lineageos.snap")) ||
		(!strcmp(name, "com.teslacoilsw.launcher")) ||
		(!strcmp(name, "com.Tele.GCam")) ||
		(!strcmp(name, "com.google.android.Redmi4X")) ||
		(!strcmp(name, "com.teslacoilsw.launcher")) ||
		(!strcmp(name, "com.android.launcher3")) ||
		(!strcmp(name, "com.google.android.apps.nexuslauncher")) ||
		(!strcmp(name, "ch.deletescape.lawnchair.plah")) ||
		(!strcmp(name, "com.google.android.launcher")) ||
		(!strcmp(name, "ru.whatau.cpl")) ||
		(!strcmp(name, "amirz.rootless.nexuslauncher")) ||
		(!strcmp(name, "com.google.android.GooglrCamera")) ||
		(!strcmp(name, "ch.deletescape.lawnchair.ci")) ||
		(!strcmp(name, "com.bsgmod.camera")) ||
		(!strcmp(name, "com.whatsapp")) ||		
		(!strcmp(name, "com.android.contacts")) ||
		(!strcmp(name, "com.android.mms")) ||
		(!strcmp(name, "com.xiaomi.hm.health")) ||
		(!strcmp(name, "com.mi.android.globallauncher")) ||
		(!strcmp(name, ".android.camera"))||
		(!strcmp(name, "com.huawei.health"))||
		(!strcmp(name, "com.android.chrome"))||
		(!strcmp(name, "com.google.android.youtube"))||
		(!strcmp(name, "com.spotify.music"))||
		(!strcmp(name, "jp.naver.line.android")))
	{
		ret = true;
	}

	return ret;
}

static unsigned long lowmem_scan(struct shrinker *s, struct shrink_control *sc)
{
	struct task_struct *tsk;
	struct task_struct *selected = NULL;
	unsigned long rem = 0;
	int tasksize;
	int i;
	short min_score_adj = OOM_SCORE_ADJ_MAX + 1;
	int minfree = 0;
	int selected_tasksize = 0;
	short selected_oom_score_adj;
	int array_size = ARRAY_SIZE(lowmem_adj);
	int other_free = global_page_state(NR_FREE_PAGES) - totalreserve_pages;
	int other_file = global_page_state(NR_FILE_PAGES) -
						global_page_state(NR_SHMEM) -
						global_page_state(NR_UNEVICTABLE) -
						total_swapcache_pages();

	if (lowmem_adj_size < array_size)
		array_size = lowmem_adj_size;
	if (lowmem_minfree_size < array_size)
		array_size = lowmem_minfree_size;
	for (i = 0; i < array_size; i++) {
		minfree = lowmem_minfree[i] +
			  ((extra_free_kbytes * 1024) / PAGE_SIZE);
		if (other_free < minfree && other_file < minfree) {
			min_score_adj = lowmem_adj[i];
			break;
		}
	}

	lowmem_print(3, "lowmem_scan %lu, %x, ofree %d %d, ma %hd\n",
			sc->nr_to_scan, sc->gfp_mask, other_free,
			other_file, min_score_adj);

	if (min_score_adj == OOM_SCORE_ADJ_MAX + 1) {
//		trace_almk_shrink(0, ret, other_free, other_file, 0);
		lowmem_print(5, "lowmem_scan %lu, %x, return 0\n",
			     sc->nr_to_scan, sc->gfp_mask);
		return 0;
	}

	selected_oom_score_adj = min_score_adj;

	rcu_read_lock();
	for_each_process(tsk) {
		struct task_struct *p;
		short oom_score_adj;

		if (tsk->flags & PF_KTHREAD)
			continue;

		/* if task no longer has any memory ignore it */
		if (test_task_flag(tsk, TIF_MM_RELEASED))
			continue;

		if (oom_reaper) {
			p = find_lock_task_mm(tsk);
			if (!p)
				continue;

			if (test_bit(MMF_OOM_VICTIM, &p->mm->flags)) {
				if (test_bit(MMF_OOM_SKIP, &p->mm->flags)) {
					task_unlock(p);
					continue;
				} else if (time_before_eq(jiffies,
						lowmem_deathpending_timeout)) {
					task_unlock(p);
					rcu_read_unlock();
					mutex_unlock(&scan_mutex);
					return 0;
				}
			}
		} else {
			if (time_before_eq(jiffies,
					   lowmem_deathpending_timeout))
				if (test_task_lmk_waiting(tsk)) {
					rcu_read_unlock();
					mutex_unlock(&scan_mutex);
					return 0;
				}

			p = find_lock_task_mm(tsk);
			if (!p)
				continue;
		}

		if (test_tsk_thread_flag(p, TIF_MEMDIE) &&
		    time_before_eq(jiffies, lowmem_deathpending_timeout)) {
			task_unlock(p);
			rcu_read_unlock();
			return 0;
		}
		oom_score_adj = p->signal->oom_score_adj;
		if (oom_score_adj < min_score_adj) {
			task_unlock(p);
			continue;
		}
		tasksize = get_mm_rss(p->mm);
		task_unlock(p);
		if ((tasksize <= 0) || (lowmem_whitelist(p->comm) == true))
			continue;
		if (selected) {
			if (oom_score_adj < selected_oom_score_adj)
				continue;
			if (oom_score_adj == selected_oom_score_adj &&
			    tasksize <= selected_tasksize)
				continue;
		}
		selected = p;
		selected_tasksize = tasksize;
		selected_oom_score_adj = oom_score_adj;
		lowmem_print(2, "select '%s' (%d), adj %hd, size %d, to kill\n",
			     p->comm, p->pid, oom_score_adj, tasksize);
	}
	if (selected) {
		long cache_size = other_file * (long)(PAGE_SIZE / 1024);
		long cache_limit = minfree * (long)(PAGE_SIZE / 1024);
		long free = other_free * (long)(PAGE_SIZE / 1024);


		if (test_task_flag(selected, TIF_MEMDIE) &&
		    (test_task_state(selected, TASK_UNINTERRUPTIBLE))) {
			lowmem_print(2, "'%s' (%d) is already killed\n",
				     selected->comm,
				     selected->pid);
			rcu_read_unlock();
			mutex_unlock(&scan_mutex);
			return 0;
		}

		task_lock(selected);
		send_sig(SIGKILL, selected, 0);
		if (selected->mm) {
			task_set_lmk_waiting(selected);
			if (!test_bit(MMF_OOM_SKIP, &selected->mm->flags) &&
			    oom_reaper) {
				mark_lmk_victim(selected);
				wake_oom_reaper(selected);
			}
		}
		task_unlock(selected);
//		trace_lowmemory_kill(selected, cache_size, cache_limit, free);
		lowmem_print(1, "Killing '%s' (%d) (tgid %d), adj %hd,\n" \
			        "   to free %ldkB on behalf of '%s' (%d) because\n" \
			        "   cache %ldkB is below limit %ldkB for oom_score_adj %hd\n" \
			        "   Free memory is %ldkB above reserved\n",
			     selected->comm, selected->pid, selected->tgid,
			     selected_oom_score_adj,
			     selected_tasksize * (long)(PAGE_SIZE / 1024),
			     current->comm, current->pid,
			     cache_size, cache_limit,
			     min_score_adj,
			     free);
		lowmem_deathpending_timeout = jiffies + HZ;
		rem += selected_tasksize;
		rcu_read_unlock();
		/* give the system time to free up the memory */
		msleep_interruptible(20);
//		trace_almk_shrink(selected_tasksize, ret,
//				  other_free, other_file,
//				  selected_oom_score_adj);
	} else {
//		trace_almk_shrink(1, ret, other_free, other_file, 0);
		rcu_read_unlock();
	}

	lowmem_print(4, "lowmem_scan %lu, %x, return %lu\n",
		     sc->nr_to_scan, sc->gfp_mask, rem);
	rcu_read_unlock();
	return rem;
}

static struct shrinker lowmem_shrinker = {
	.scan_objects = lowmem_scan,
	.count_objects = lowmem_count,
	.seeks = DEFAULT_SEEKS * 16
};

static int __init lowmem_init(void)
{
	register_shrinker(&lowmem_shrinker);
	lmk_event_init();
	return 0;
}
device_initcall(lowmem_init);

#ifdef CONFIG_ANDROID_LOW_MEMORY_KILLER_AUTODETECT_OOM_ADJ_VALUES
static short lowmem_oom_adj_to_oom_score_adj(short oom_adj)
{
	if (oom_adj == OOM_ADJUST_MAX)
		return OOM_SCORE_ADJ_MAX;
	else
		return (oom_adj * OOM_SCORE_ADJ_MAX) / -OOM_DISABLE;
}

static void lowmem_autodetect_oom_adj_values(void)
{
	int i;
	short oom_adj;
	short oom_score_adj;
	int array_size = ARRAY_SIZE(lowmem_adj);

	if (lowmem_adj_size < array_size)
		array_size = lowmem_adj_size;

	if (array_size <= 0)
		return;

	oom_adj = lowmem_adj[array_size - 1];
	if (oom_adj > OOM_ADJUST_MAX)
		return;

	oom_score_adj = lowmem_oom_adj_to_oom_score_adj(oom_adj);
	if (oom_score_adj <= OOM_ADJUST_MAX)
		return;

	lowmem_print(1, "lowmem_shrink: convert oom_adj to oom_score_adj:\n");
	for (i = 0; i < array_size; i++) {
		oom_adj = lowmem_adj[i];
		oom_score_adj = lowmem_oom_adj_to_oom_score_adj(oom_adj);
		lowmem_adj[i] = oom_score_adj;
		lowmem_print(1, "oom_adj %d => oom_score_adj %d\n",
			     oom_adj, oom_score_adj);
	}
}

static int lowmem_adj_array_set(const char *val, const struct kernel_param *kp)
{
	int ret;

	ret = param_array_ops.set(val, kp);

	/* HACK: Autodetect oom_adj values in lowmem_adj array */
	lowmem_autodetect_oom_adj_values();

	return ret;
}

static int lowmem_adj_array_get(char *buffer, const struct kernel_param *kp)
{
	return param_array_ops.get(buffer, kp);
}

static void lowmem_adj_array_free(void *arg)
{
	param_array_ops.free(arg);
}

static struct kernel_param_ops lowmem_adj_array_ops = {
	.set = lowmem_adj_array_set,
	.get = lowmem_adj_array_get,
	.free = lowmem_adj_array_free,
};

static const struct kparam_array __param_arr_adj = {
	.max = ARRAY_SIZE(lowmem_adj),
	.num = &lowmem_adj_size,
	.ops = &param_ops_short,
	.elemsize = sizeof(lowmem_adj[0]),
	.elem = lowmem_adj,
};
#endif

/*
 * not really modular, but the easiest way to keep compat with existing
 * bootargs behaviour is to continue using module_param here.
 */
module_param_named(cost, lowmem_shrinker.seeks, int, S_IRUGO | S_IWUSR);
#ifdef CONFIG_ANDROID_LOW_MEMORY_KILLER_AUTODETECT_OOM_ADJ_VALUES
module_param_cb(adj, &lowmem_adj_array_ops,
		.arr = &__param_arr_adj,
		S_IRUGO | S_IWUSR);
__MODULE_PARM_TYPE(adj, "array of short");
#else
module_param_array_named(adj, lowmem_adj, short, &lowmem_adj_size,
			 S_IRUGO | S_IWUSR);
#endif
module_param_array_named(minfree, lowmem_minfree, uint, &lowmem_minfree_size,
			 S_IRUGO | S_IWUSR);
module_param_named(debug_level, lowmem_debug_level, uint, S_IRUGO | S_IWUSR);

