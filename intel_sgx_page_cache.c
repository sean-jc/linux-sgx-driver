/*
 * This file is provided under a dual BSD/GPLv2 license.  When using or
 * redistributing this file, you may do so under either license.
 *
 * GPL LICENSE SUMMARY
 *
 * Copyright(c) 2016 Intel Corporation.
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
 * Jarkko Sakkinen <jarkko.sakkinen@linux.intel.com>
 * Intel Finland Oy - BIC 0357606-4 - Westendinkatu 7, 02160 Espoo
 *
 * BSD LICENSE
 *
 * Copyright(c) 2016 Intel Corporation.
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
 * Jarkko Sakkinen <jarkko.sakkinen@linux.intel.com>
 * Suresh Siddha <suresh.b.siddha@intel.com>
 * Serge Ayoun <serge.ayoun@intel.com>
 * Shay Katz-zamir <shay.katz-zamir@intel.com>
 */

#include "intel_sgx.h"
#include <linux/freezer.h>
#include <linux/highmem.h>
#include <linux/kthread.h>
#include <linux/ratelimit.h>
#include <linux/sched.h>
#include <linux/slab.h>

static LIST_HEAD(sgx_free_list);
static DEFINE_SPINLOCK(sgx_free_list_lock);

static LIST_HEAD(sgx_va_pages);
static DECLARE_RWSEM(sgx_va_pages_sem);

LIST_HEAD(sgx_tgid_ctx_list);
DEFINE_MUTEX(sgx_tgid_ctx_mutex);
static unsigned int sgx_nr_total_epc_pages;
static unsigned int sgx_nr_free_pages;
static unsigned int sgx_nr_low_pages = SGX_NR_LOW_EPC_PAGES_DEFAULT;
static unsigned int sgx_nr_high_pages;
struct task_struct *kisgxswapd_tsk;
static DECLARE_WAIT_QUEUE_HEAD(kisgxswapd_waitq);

static struct sgx_tgid_ctx *sgx_isolate_tgid_ctx(unsigned long nr_to_scan)
{
	struct sgx_tgid_ctx *ctx = NULL;
	int i;

	mutex_lock(&sgx_tgid_ctx_mutex);

	if (list_empty(&sgx_tgid_ctx_list)) {
		mutex_unlock(&sgx_tgid_ctx_mutex);
		return NULL;
	}

	for (i = 0; i < nr_to_scan; i++) {
		/* Peek TGID context from the head. */
		ctx = list_first_entry(&sgx_tgid_ctx_list,
				       struct sgx_tgid_ctx,
				       list);

		/* Move to the tail so that we do not encounter it in the
		 * next iteration.
		 */
		list_move_tail(&ctx->list, &sgx_tgid_ctx_list);

		/* Non-empty TGID context? */
		if (!list_empty(&ctx->encl_list) &&
		    kref_get_unless_zero(&ctx->refcount))
			break;

		ctx = NULL;
	}

	mutex_unlock(&sgx_tgid_ctx_mutex);

	return ctx;
}

static struct sgx_encl *sgx_isolate_encl(struct sgx_tgid_ctx *ctx,
					       unsigned long nr_to_scan)
{
	struct sgx_encl *encl = NULL;
	int i;

	mutex_lock(&sgx_tgid_ctx_mutex);

	if (list_empty(&ctx->encl_list)) {
		mutex_unlock(&sgx_tgid_ctx_mutex);
		return NULL;
	}

	for (i = 0; i < nr_to_scan; i++) {
		/* Peek encl from the head. */
		encl = list_first_entry(&ctx->encl_list, struct sgx_encl,
					encl_list);

		/* Move to the tail so that we do not encounter it in the
		 * next iteration.
		 */
		list_move_tail(&encl->encl_list, &ctx->encl_list);

		/* Enclave with faulted pages?  */
		if (!list_empty(&encl->load_list) &&
		    kref_get_unless_zero(&encl->refcount))
			break;

		encl = NULL;
	}

	mutex_unlock(&sgx_tgid_ctx_mutex);

	return encl;
}

static void sgx_isolate_pages(struct sgx_encl *encl,
			      struct list_head *dst,
			      unsigned long nr_to_scan)
{
	struct sgx_encl_page *entry;
	int i;

	mutex_lock(&encl->lock);

	for (i = 0; i < nr_to_scan; i++) {
		if (list_empty(&encl->load_list))
			break;

		entry = list_first_entry(&encl->load_list,
					 struct sgx_encl_page,
					 load_list);

		if (!(entry->flags & SGX_ENCL_PAGE_RESERVED)) {
			entry->flags |= SGX_ENCL_PAGE_RESERVED;
			list_move_tail(&entry->load_list, dst);
		} else {
			list_move_tail(&entry->load_list, &encl->load_list);
		}
	}

	mutex_unlock(&encl->lock);
}

static void sgx_ipi_cb(void *info)
{
}

static void sgx_eblock(struct sgx_epc_page *epc_page)
{
	void *vaddr = sgx_get_epc_page(epc_page);
	BUG_ON(__eblock((unsigned long)vaddr));
	sgx_put_epc_page(vaddr);
}

static void sgx_etrack(struct sgx_epc_page *epc_page)
{
	void *epc = sgx_get_epc_page(epc_page);
	BUG_ON(__etrack(epc));
	sgx_put_epc_page(epc);
}

static int sgx_ewb(struct sgx_encl *encl,
		   struct sgx_encl_page *encl_page,
		   struct page *backing)
{
	struct sgx_page_info pginfo;
	void *epc;
	void *va;
	int ret;

	pginfo.srcpge = (unsigned long)kmap_atomic(backing);
	epc = sgx_get_epc_page(encl_page->epc_page);
	va = sgx_get_epc_page(encl_page->va_page->epc_page);

	pginfo.pcmd = (unsigned long)&encl_page->pcmd;
	pginfo.linaddr = 0;
	pginfo.secs = 0;
	ret = __ewb(&pginfo, epc,
		    (void *)((unsigned long)va + encl_page->va_offset));

	sgx_put_epc_page(va);
	sgx_put_epc_page(epc);
	kunmap_atomic((void *)(unsigned long)pginfo.srcpge);

	/* Overwriting VA slots is allowed and is expected when reusing stale
	 * slots, i.e. slots used for evicted pages whose application/enclave
	 * has exited.
	 */
	if (ret == SGX_VA_SLOT_OCCUPIED)
		ret = 0;

	if (ret != 0 && ret != SGX_NOT_TRACKED)
		sgx_err(encl, "EWB returned %d\n", ret);

	return ret;
}

void sgx_free_encl_page(struct sgx_encl_page *entry,
		    struct sgx_encl *encl,
		    unsigned int flags)
{
	sgx_free_page(entry->epc_page, encl, flags);
	entry->epc_page = NULL;
	entry->flags &= ~SGX_ENCL_PAGE_RESERVED;
}

static void sgx_write_pages(struct list_head *src)
{
	struct sgx_encl *encl;
	struct sgx_encl_page *entry;
	struct sgx_encl_page *tmp;
	struct page *pages[SGX_NR_SWAP_CLUSTER_MAX + 1];
	struct sgx_vma *evma;
	int cnt = 0;
	int i = 0;
	int ret;

	if (list_empty(src))
		return;

	entry = list_first_entry(src, struct sgx_encl_page, load_list);
	encl = entry->encl;

	if (!sgx_pin_mm(encl)) {
		while (!list_empty(src)) {
			entry = list_first_entry(src, struct sgx_encl_page,
						 load_list);
			list_del(&entry->load_list);
			mutex_lock(&encl->lock);
			sgx_free_encl_page(entry, encl, 0);
			mutex_unlock(&encl->lock);
		}

		return;
	}

	/* EBLOCK */

	list_for_each_entry_safe(entry, tmp, src, load_list) {
		mutex_lock(&encl->lock);
		evma = sgx_find_vma(encl, entry->addr);
		if (!evma) {
			list_del(&entry->load_list);
			sgx_free_encl_page(entry, encl, 0);
			mutex_unlock(&encl->lock);
			continue;
		}

		pages[cnt] = sgx_get_backing(encl, entry);
		if (IS_ERR(pages[cnt])) {
			list_del(&entry->load_list);
			list_add_tail(&entry->load_list, &encl->load_list);
			entry->flags &= ~SGX_ENCL_PAGE_RESERVED;
			mutex_unlock(&encl->lock);
			continue;
		}

		zap_vma_ptes(evma->vma, entry->addr, PAGE_SIZE);
		sgx_eblock(entry->epc_page);
		cnt++;
		mutex_unlock(&encl->lock);
	}

	/* ETRACK */

	mutex_lock(&encl->lock);
	sgx_etrack(encl->secs_page.epc_page);
	mutex_unlock(&encl->lock);

	/* EWB */

	mutex_lock(&encl->lock);
	i = 0;

	while (!list_empty(src)) {
		entry = list_first_entry(src, struct sgx_encl_page,
					 load_list);
		list_del(&entry->load_list);

		evma = sgx_find_vma(encl, entry->addr);
		if (evma) {
			ret = sgx_ewb(encl, entry, pages[i]);
			BUG_ON(ret != 0 && ret != SGX_NOT_TRACKED);
			/* Only kick out threads with an IPI if needed. */
			if (ret) {
				smp_call_function(sgx_ipi_cb, NULL, 1);
				BUG_ON(sgx_ewb(encl, entry, pages[i]));
			}
			encl->secs_child_cnt--;
		}

		sgx_free_encl_page(entry, encl,
				      evma ? SGX_FREE_SKIP_EREMOVE : 0);
		sgx_put_backing(pages[i++], evma);
	}

	/* Allow SECS page eviction only when the encl is initialized. */
	if (!encl->secs_child_cnt &&
	    (encl->flags & SGX_ENCL_INITIALIZED)) {
		pages[cnt] = sgx_get_backing(encl, &encl->secs_page);
		if (!IS_ERR(pages[cnt])) {
			ret = sgx_ewb(encl, &encl->secs_page,
				      pages[cnt]);
			BUG_ON(ret);
			encl->flags |= SGX_ENCL_SECS_EVICTED;

			sgx_free_encl_page(&encl->secs_page, encl,
					      SGX_FREE_SKIP_EREMOVE);
			sgx_put_backing(pages[cnt], true);
		}
	}

	mutex_unlock(&encl->lock);

	sgx_unpin_mm(encl);
}

static void sgx_swap_pages(unsigned long nr_to_scan)
{
	struct sgx_tgid_ctx *ctx;
	struct sgx_encl *encl;
	LIST_HEAD(cluster);

	ctx = sgx_isolate_tgid_ctx(nr_to_scan);
	if (!ctx)
		return;

	encl = sgx_isolate_encl(ctx, nr_to_scan);
	if (!encl)
		goto out;

	sgx_isolate_pages(encl, &cluster, nr_to_scan);
	sgx_write_pages(&cluster);

	kref_put(&encl->refcount, sgx_encl_release);
out:
	kref_put(&ctx->refcount, sgx_tgid_ctx_release);
}

int kisgxswapd(void *p)
{
	DEFINE_WAIT(wait);
	unsigned int nr_free;
	unsigned int nr_high;

	for ( ; ; ) {
		if (kthread_should_stop())
			break;

		spin_lock(&sgx_free_list_lock);
		nr_free = sgx_nr_free_pages;
		nr_high = sgx_nr_high_pages;
		spin_unlock(&sgx_free_list_lock);

		if (nr_free < nr_high) {
			sgx_swap_pages(SGX_NR_SWAP_CLUSTER_MAX);
			schedule();
		} else {
			prepare_to_wait(&kisgxswapd_waitq,
					&wait, TASK_INTERRUPTIBLE);

			if (!kthread_should_stop())
				schedule();

			finish_wait(&kisgxswapd_waitq, &wait);
		}
	}

	pr_info("%s: done\n", __func__);
	return 0;
}

int sgx_page_cache_init(resource_size_t start, unsigned long size)
{
	unsigned long i;
	struct sgx_epc_page *new_epc_page, *entry;
	struct list_head *parser, *temp;

	for (i = 0; i < size; i += PAGE_SIZE) {
		new_epc_page = kzalloc(sizeof(*new_epc_page), GFP_KERNEL);
		if (!new_epc_page)
			goto err_freelist;
		new_epc_page->pa = start + i;

		spin_lock(&sgx_free_list_lock);
		list_add_tail(&new_epc_page->free_list, &sgx_free_list);
		sgx_nr_total_epc_pages++;
		sgx_nr_free_pages++;
		spin_unlock(&sgx_free_list_lock);
	}

	sgx_nr_high_pages = 2 * sgx_nr_low_pages;
	kisgxswapd_tsk = kthread_run(kisgxswapd, NULL, "kisgxswapd");

	return 0;
err_freelist:
	list_for_each_safe(parser, temp, &sgx_free_list) {
		spin_lock(&sgx_free_list_lock);
		entry = list_entry(parser, struct sgx_epc_page, free_list);
		list_del(&entry->free_list);
		spin_unlock(&sgx_free_list_lock);
		kfree(entry);
	}
	return -ENOMEM;
}

void sgx_page_cache_teardown(void)
{
	struct sgx_epc_page *entry;
	struct list_head *parser, *temp;

	if (kisgxswapd_tsk)
		kthread_stop(kisgxswapd_tsk);

	spin_lock(&sgx_free_list_lock);
	list_for_each_safe(parser, temp, &sgx_free_list) {
		entry = list_entry(parser, struct sgx_epc_page, free_list);
		list_del(&entry->free_list);
		kfree(entry);
	}
	spin_unlock(&sgx_free_list_lock);
}

static struct sgx_epc_page *sgx_alloc_page_fast(void)
{
	struct sgx_epc_page *entry = NULL;

	spin_lock(&sgx_free_list_lock);

	if (!list_empty(&sgx_free_list)) {
		entry = list_first_entry(&sgx_free_list, struct sgx_epc_page,
					 free_list);
		list_del(&entry->free_list);
		sgx_nr_free_pages--;
	}

	spin_unlock(&sgx_free_list_lock);

	return entry;
}

/**
 * sgx_alloc_page - alloc an EPC page
 * @ctx:	enclave accounting for the thread group (can be NULL)
 * @flags:	allocation flags
 *
 * Return: an EPC page or an error code
 */
struct sgx_epc_page *sgx_alloc_page(struct sgx_tgid_ctx *ctx,
				    unsigned int flags)
{
	struct sgx_epc_page *entry;

	for ( ; ; ) {
		entry = sgx_alloc_page_fast();
		if (entry) {
			if (ctx)
				atomic_inc(&ctx->epc_cnt);
			break;
		} else if (flags & SGX_ALLOC_ATOMIC) {
			entry = ERR_PTR(-EBUSY);
			break;
		}

		if (signal_pending(current)) {
			entry = ERR_PTR(-ERESTARTSYS);
			break;
		}

		sgx_swap_pages(SGX_NR_SWAP_CLUSTER_MAX);
		schedule();
	}

	if (sgx_nr_free_pages < sgx_nr_low_pages)
		wake_up(&kisgxswapd_waitq);

	return entry;
}

/**
 * sgx_free_page - free an EPC page
 * @entry:	an EPC page
 * @encl:	the enclave who owns the EPC page
 * @flags:	free flags
 */
void sgx_free_page(struct sgx_epc_page *entry,
		   struct sgx_encl *encl,
		   unsigned int flags)
{
	void *epc;
	int ret;

	if (encl) {
		atomic_dec(&encl->tgid_ctx->epc_cnt);

		if (encl->flags & SGX_ENCL_SUSPEND)
			flags |= SGX_FREE_SKIP_EREMOVE;
	}

	if (!(flags & SGX_FREE_SKIP_EREMOVE)) {
		epc = sgx_get_epc_page(entry);
		ret = __eremove(epc);
		sgx_put_epc_page(epc);

		if (ret) {
			pr_err("EREMOVE returned %d\n", ret);
			BUG();
		}
	}

	spin_lock(&sgx_free_list_lock);
	list_add(&entry->free_list, &sgx_free_list);
	sgx_nr_free_pages++;
	spin_unlock(&sgx_free_list_lock);
}

/**
 * sgx_alloc_va_page() - Allocate a VA page (if necessary) for the encl page
 * @enclave_page	the enclave page to be associated with the VA slot
 *
 * Allocates VA slot for the enclave page and fills in the appropriate fields.
 * Returns a POSIX error code on failure.  Allocates a new VA page in the EPC
 * if there are no VA slots available.
 */
int sgx_alloc_va_page(struct sgx_encl_page *encl_page)
{
	struct sgx_va_page *va_page;
	struct sgx_epc_page *epc_page = NULL;
	unsigned int va_offset = PAGE_SIZE;
	void *vaddr;
	int ret;

	down_read(&sgx_va_pages_sem);
	list_for_each_entry(va_page, &sgx_va_pages, list) {
		va_offset = sgx_alloc_va_slot(va_page);
		if (va_offset < PAGE_SIZE)
			break;
	}
	up_read(&sgx_va_pages_sem);

	if (va_offset == PAGE_SIZE) {
		va_page = kzalloc(sizeof(*va_page), GFP_KERNEL);
		if (!va_page)
			return -ENOMEM;

		epc_page = sgx_alloc_page(NULL, 0);
		if (IS_ERR(epc_page)) {
			kfree(va_page);
			return PTR_ERR(epc_page);
		}

		vaddr = sgx_get_epc_page(epc_page);
		BUG_ON(!vaddr);
		ret = __epa(vaddr);
		sgx_put_epc_page(vaddr);
		if (ret) {
			pr_err("isgx: EPA returned %d\n", ret);
			sgx_free_page(epc_page, NULL, 0);
			kfree(va_page);
			/* This probably a driver bug. Better to crash cleanly
			 * than let the failing driver to run.
			 */
			BUG();
		}

		va_page->epc_page = epc_page;
		va_offset = sgx_alloc_va_slot(va_page);
		BUG_ON(va_offset >= PAGE_SIZE);

		down_write(&sgx_va_pages_sem);
		list_add(&va_page->list, &sgx_va_pages);
		up_write(&sgx_va_pages_sem);
	}

	encl_page->va_page = va_page;
	encl_page->va_offset = va_offset;

	return 0;
}

/* sgx_free_va_page() - Conditionally removes a VA page from the EPC
 * @va_page		VA page to free
 *
 * It's possible a different thread allocated a slot in this VA page
 * while we were waiting for the semaphore.  Re-check the number of
 * used slots after acquiring the semaphore for writing.  Check the
 * list itself for validity to as a a different thread (or threads)
 * could have allocated and then freed (the last) slot while we were
 * waiting for the semaphore, creating a race to free the VA page.
 */
void sgx_free_va_page(struct sgx_va_page *va_page)
{
	down_write(&sgx_va_pages_sem);
	if (likely(atomic_read(&va_page->used) == 0 && !list_empty(&va_page->list))) {
		BUG_ON(find_first_bit(va_page->slots, SGX_VA_SLOT_COUNT) != SGX_VA_SLOT_COUNT);
		list_del_init(&va_page->list);
		sgx_free_page(va_page->epc_page, NULL, 0);
		kfree(va_page);
	}
	up_write(&sgx_va_pages_sem);
}
