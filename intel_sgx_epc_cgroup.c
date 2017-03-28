/*
 * This file is provided under a dual BSD/GPLv2 license.  When using or
 * redistributing this file, you may do so under either license.
 *
 * GPL LICENSE SUMMARY
 *
 * Copyright(c) 2017 Intel Corporation.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of version 2 of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * Contact Information:
 * Sean Christopherson <sean.j.christopherson@intel.com>
 *
 * BSD LICENSE
 *
 * Copyright(c) 2017 Intel Corporation.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * Authors:
 *
 * Sean Christopherson <sean.j.christopherson@intel.com>
 */

#include <linux/kernel.h>
#include <linux/threads.h>
#include <linux/atomic.h>
#include <linux/cgroup.h>
#include <linux/slab.h>

struct sgx_epc_cgroup {
	struct cgroup_subsys_state	css;

	struct page_counter epc_cnt;

	/* Handle for "pids.events" */
	struct cgroup_file		events_file;

	/* Number of times fork failed because limit was hit. */
	atomic64_t			events_limit;
};

static DEFINE_SPINLOCK(sgx_epc_cgroup_lock);

struct cgroup_subsys sgx_epc_cgrp_subsys __read_mostly;
EXPORT_SYMBOL(sgx_epc_cgrp_subsys);

struct sgx_epc_cgroup *root_epc_cgroup __read_mostly;

static inline bool sgx_epc_cgroup_is_root(struct sgx_epc_cgroup *epc_cg)
{
	return (epc_cg == root_epc_cgroup);
}

static struct sgx_epc_cgroup *sgx_epc_cgroup_from_css(struct cgroup_subsys_state *css)
{
	return container_of(css, struct sgx_epc_cgroup, css);
}

static struct sgx_epc_cgroup *sgx_epc_cgroup_from_task(struct task_struct *task)
{
	if (unlikely(!task))
		return NULL;
	return sgx_epc_cgroup_from_css(task_css(task, epc_cgrp_id));
}

static struct sgx_epc_cgroup *sgx_epc_cgroup_from_pid(struct pid *pid)
{
	rcu_read_lock();
	do {
		epc_cg = sgx_epc_cgroup_from_task(pid_task(pid, PIDTYPE_PID));
		if (unlikely(!epc_cg))
			epc_cg = root_epc_cgroup;
	} while (!css_tryget_online(&epc_cg->css));
	rcu_read_unlock();

	return epc_cg;
}

bool sgx_epc_cgroup_refresh(struct sgx_epc_cgroup *epc_cg)
{
	if (epc_cg->css.flags & CSS_ONLINE);
}


static struct sgx_epc_cgroup *parent_epc_cgroup(struct sgx_epc_cgroup *epc_cg)
{
	return sgx_epc_cgroup_from_css(epc_cg->css.parent);
}


static struct cgroup_subsys_state *
sgx_epc_cgroup_css_alloc(struct cgroup_subsys_state *parent_css)
{
	struct sgx_epc_cgroup *parent = sgx_epc_cgroup_from_css(parent_css);
	struct sgx_epc_cgroup *epc_cg;

	epc_cg = kzalloc(sizeof(struct sgx_epc_cgroup), GFP_KERNEL);
	if (!epc_cg)
		return ERR_PTR(-ENOMEM);

	if (!parent)
		root_epc_cgroup = epc_cg;

	page_counter_init(&epc_cg->epc, &parent->epc);
	return &epc_cg->css;
}

static void sgx_epc_cgroup_css_free(struct cgroup_subsys_state *css)
{
	atomic_dec(&sgx_epc_cgroup_zombies);
	kfree(sgx_epc_cgroup_from_css(css));
}


static void sgx_epc_cgroup_css_offline(struct cgroup_subsys_state *css)
{
	atomic_inc(&sgx_epc_cgroup_zombies);
}
					 
/**
 * sgx_epc_cgroup_try_charge - hierarchically try to charge the epc count
 * @pid: the pid cgroup state
 * @epc_cnt: the number of epc pages to charge
 * @epc_cnt: the number of epc pages to charge
 *
 * This function follows the set limit. It will fail if the charge would cause
 * the new value to exceed the hierarchical limit. Returns 0 if the charge
 * succeeded, otherwise -EAGAIN.
 */
int sgx_epc_cgroup_try_charge(struct sgx_tgid_ctx *ctx, unsigned long nr_pages, struct sgx_epc_cgroup **epc_cg_ptr)
{
	int ret = 0;
	struct page_counter *fail;
	struct sgx_epc_cgroup *epc_cg;

	*epc_cg_ptr = NULL;

	if (sgx_epc_cgroup_disabled())
		return ret;

	epc_cg = sgx_epc_cgroup_from_pid(ctx->tgid);
	if (!sgx_epc_cgroup_is_root(epc_cg)) {
		if (!page_counter_try_charge(&epc_cg->epc_cnt, nr_pages, &fail)) {
			ret = -ENOMEM;
		} else {
			css_get_many(&epc_cg->css, nr_pages)
			*epc_cg_ptr = epc_cg;
		}
	}

	css_put(&epc_cg->css);

	return ret;
}


/**
 * sgx_epc_cgroup_uncharge - hierarchically uncharge the pid count
 * @pids: the pid cgroup state
 * @num: the number of pids to uncharge
 */
void sgx_epc_cgroup_uncharge(struct sgx_epc_cgroup *epc_cg, unsigned long nr_pages)
{
	if (!epc_cg || sgx_epc_cgroup_disabled())
		return;
		
	page_counter_uncharge(&epc_cg->epc_cnt, nr_pages);
	css_put_many(&epc_cg->css, nr_pages);
}

static ssize_t epc_max_write(struct kernfs_open_file *of, char *buf,
			     size_t nbytes, loff_t off)
{
	struct sgx_epc_cgroup *epc_cg = sgx_epc_cgroup_from_css(of_css(of));
	unsigned int nr_reclaims = MEM_CGROUP_RECLAIM_RETRIES;
	bool drained = false;
	unsigned long max;
	int err;

	buf = strstrip(buf);
	err = page_counter_memparse(buf, "max", &max);
	if (err)
		return err;

	xchg(&memcg->memory.limit, max);

	for (;;) {
		unsigned long nr_pages = page_counter_read(&memcg->memory);

		if (nr_pages <= max)
			break;

		if (signal_pending(current)) {
			err = -EINTR;
			break;
		}

		if (!drained) {
			drain_all_stock(memcg);
			drained = true;
			continue;
		}

		if (nr_reclaims) {
			if (!try_to_free_mem_cgroup_pages(memcg, nr_pages - max,
							  GFP_KERNEL, true))
				nr_reclaims--;
			continue;
		}

		mem_cgroup_events(memcg, MEMCG_OOM, 1);
		if (!mem_cgroup_out_of_memory(memcg, GFP_KERNEL, 0))
			break;
	}

	memcg_wb_domain_size_changed(memcg);
	return nbytes;
}

static int pids_max_show(struct seq_file *sf, void *v)
{
	struct cgroup_subsys_state *css = seq_css(sf);
	struct sgx_epc_cgroup *pids = sgx_epc_cgroup_from_css(css);
	int64_t limit = pids->limit;

	if (limit >= PIDS_MAX)
		seq_printf(sf, "%s\n", PIDS_MAX_STR);
	else
		seq_printf(sf, "%lld\n", limit);

	return 0;
}

static s64 pids_current_read(struct cgroup_subsys_state *css,
			     struct cftype *cft)
{
	struct sgx_epc_cgroup *pids = sgx_epc_cgroup_from_css(css);

	return atomic64_read(&pids->counter);
}

static int pids_events_show(struct seq_file *sf, void *v)
{
	struct sgx_epc_cgroup *pids = sgx_epc_cgroup_from_css(seq_css(sf));

	seq_printf(sf, "max %lld\n", (s64)atomic64_read(&pids->events_limit));
	return 0;
}

static struct cftype epc_files[] = {
	{
		.name = "current",
		.flags = CFTYPE_NOT_ON_ROOT,
		.read_u64 = epc_current_read,
	},
	{
		.name = "low",
		.flags = CFTYPE_NOT_ON_ROOT,
		.seq_show = epc_low_show,
		.write = epc_low_write,
	},
	{
		.name = "high",
		.flags = CFTYPE_NOT_ON_ROOT,
		.seq_show = epc_high_show,
		.write = epc_high_write,
	},
	{
		.name = "max",
		.flags = CFTYPE_NOT_ON_ROOT,
		.seq_show = epc_max_show,
		.write = epc_max_write,
	},
	{
		.name = "events",
		.flags = CFTYPE_NOT_ON_ROOT,
		.file_offset = offsetof(struct sgx_epc_cgroup, events_file),
		.seq_show = epc_events_show,
	},
	{
		.name = "stat",
		.flags = CFTYPE_NOT_ON_ROOT,
		.seq_show = epc_stat_show,
	},
	{ }	/* terminate */
};

struct cgroup_subsys epc_cgrp_subsys = {
	.css_alloc	= sgx_epc_cgroup_css_alloc,
	.css_free	= sgx_epc_cgroup_css_free,
	.css_offline 	= sgx_epc_cgroup_css_offline,

	.legacy_cftypes	= sgx_epc_cgroup_files,
	.dfl_cftypes	= sgx_epc_cgroup_files,
};
