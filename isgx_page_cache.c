/*
 * (C) Copyright 2015 Intel Corporation
 *
 * Authors:
 *
 * Jarkko Sakkinen <jarkko.sakkinen@intel.com>
 * Suresh Siddha <suresh.b.siddha@intel.com>
 * Serge Ayoun <serge.ayoun@intel.com>
 * Shay Katz-zamir <shay.katz-zamir@intel.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; version 2
 * of the License.
 */

#include "isgx.h"
#include <linux/freezer.h>
#include <linux/highmem.h>
#include <linux/kthread.h>
#include <linux/ratelimit.h>
#include <linux/sched.h>
#include <linux/slab.h>

static LIST_HEAD(isgx_free_list);
static DEFINE_SPINLOCK(isgx_free_list_lock);

static LIST_HEAD(isgx_va_pages);
static DECLARE_RWSEM(isgx_va_pages_sem);

LIST_HEAD(isgx_tgid_ctx_list);
DEFINE_MUTEX(isgx_tgid_ctx_mutex);
unsigned int isgx_nr_total_epc_pages;
unsigned int isgx_nr_free_epc_pages;
unsigned int isgx_nr_low_epc_pages = ISGX_NR_LOW_EPC_PAGES_DEFAULT;
unsigned int isgx_nr_high_epc_pages;
struct task_struct *kisgxswapd_tsk;
static DECLARE_WAIT_QUEUE_HEAD(kisgxswapd_waitq);

static struct isgx_tgid_ctx *isolate_ctx(unsigned long nr_to_scan)
{
	struct isgx_tgid_ctx *ctx;
	int i;

	for (i = 0, ctx = NULL; i < nr_to_scan; i++, ctx = NULL) {
		schedule();

		mutex_lock(&isgx_tgid_ctx_mutex);
		if (list_empty(&isgx_tgid_ctx_list)) {
			mutex_unlock(&isgx_tgid_ctx_mutex);
			continue;
		}

		ctx = list_first_entry(&isgx_tgid_ctx_list,
				       struct isgx_tgid_ctx,
				       list);
		list_move_tail(&ctx->list, &isgx_tgid_ctx_list);

		if (kref_get_unless_zero(&ctx->refcount)) {
			mutex_unlock(&isgx_tgid_ctx_mutex);
			break;
		}

		mutex_unlock(&isgx_tgid_ctx_mutex);
		kref_put(&ctx->refcount, release_tgid_ctx);
	}

	return ctx;
}

static struct isgx_enclave *isolate_enclave(unsigned long nr_to_scan)
{
	struct isgx_enclave *encl;
	struct isgx_tgid_ctx *ctx;
	int i;

	ctx = isolate_ctx(nr_to_scan);
	if (!ctx)
		return NULL;

	for (i = 0, encl = NULL; i < nr_to_scan; i++, encl = NULL) {
		mutex_lock(&isgx_tgid_ctx_mutex);
		if (list_empty(&ctx->enclave_list)) {
			mutex_unlock(&isgx_tgid_ctx_mutex);
			break;
		}

		encl = list_first_entry(&ctx->enclave_list, struct isgx_enclave,
					enclave_list);
		list_move_tail(&encl->enclave_list, &ctx->enclave_list);
		if (kref_get_unless_zero(&encl->refcount)) {
			mutex_unlock(&isgx_tgid_ctx_mutex);
			break;
		}

		mutex_unlock(&isgx_tgid_ctx_mutex);
	}

	kref_put(&ctx->refcount, release_tgid_ctx);
	return encl;
}

static void isolate_cluster(struct list_head *dst,
			    unsigned long nr_to_scan)
{
	struct isgx_enclave *enclave;
	struct isgx_enclave_page *entry;
	int i;

	enclave = isolate_enclave(nr_to_scan);
	if (!enclave)
		return;

	if (!isgx_pin_mm(enclave)) {
		kref_put(&enclave->refcount, isgx_enclave_release);
		return;
	}

	for (i = 0; i < nr_to_scan; i++) {
		mutex_lock(&enclave->lock);
		if (list_empty(&enclave->load_list)) {
			mutex_unlock(&enclave->lock);
			break;
		}

		entry = list_first_entry(&enclave->load_list,
					 struct isgx_enclave_page,
					 load_list);

		if (!(entry->flags & ISGX_ENCLAVE_PAGE_RESERVED)) {
			if (!isgx_test_and_clear_young(entry)) {
				entry->flags |= ISGX_ENCLAVE_PAGE_RESERVED;
				list_move_tail(&entry->load_list, dst);
			} else {
				list_move_tail(&entry->load_list, &enclave->load_list);
			}
		} else {
			list_move_tail(&entry->load_list, &enclave->load_list);
		}

		mutex_unlock(&enclave->lock);
	}

	isgx_unpin_mm(enclave);
	if (list_empty(dst)) {
		kref_put(&enclave->refcount, isgx_enclave_release);
		return;
	}
}

static void isgx_ipi_cb(void *info)
{
}

static void do_eblock(struct isgx_epc_page *epc_page)
{
	void *vaddr;
	vaddr = isgx_get_epc_page(epc_page);
	BUG_ON(__eblock((unsigned long) vaddr));
	isgx_put_epc_page(vaddr);
}

static void do_etrack(struct isgx_epc_page *epc_page)
{
	void *epc;
	epc = isgx_get_epc_page(epc_page);
	BUG_ON(__etrack(epc));
	isgx_put_epc_page(epc);
}

static int do_ewb(struct isgx_enclave *enclave,
		  struct isgx_enclave_page *enclave_page,
		  struct page *backing_page)
{
	struct page_info pginfo;
	void *epc;
	void *va;
	int ret;

	pginfo.srcpge = (unsigned long) kmap_atomic(backing_page);
	epc = isgx_get_epc_page(enclave_page->epc_page);
	va = isgx_get_epc_page(enclave_page->va_page->epc_page);

	pginfo.pcmd = (unsigned long) &enclave_page->pcmd;
	pginfo.linaddr = 0;
	pginfo.secs = 0;
	ret = __ewb(&pginfo, epc,
		    (void *)((unsigned long) va + enclave_page->va_offset));

	isgx_put_epc_page(va);
	isgx_put_epc_page(epc);
	kunmap_atomic((void *) pginfo.srcpge);

	/* Overwriting VA slots is allowed and is expected when reusing stale
	 * slots, i.e. slots used for evicted pages whose application/enclave
	 * has exited.
	 */
	if (ret == ISGX_VA_SLOT_OCCUPIED)
		ret = 0;

	if (ret != 0 && ret != ISGX_NOT_TRACKED)
		isgx_err(enclave, "EWB returned %d\n", ret);

	return ret;
}


static void evict_cluster(struct list_head *src, unsigned int flags)
{
	struct isgx_enclave *enclave;
	struct isgx_enclave_page *entry;
	struct isgx_enclave_page *tmp;
	struct page *pages[ISGX_NR_SWAP_CLUSTER_MAX+1];
	struct isgx_vma *evma;
	int cnt = 0;
	int i = 0;
	int ret;

	if (list_empty(src))
		return;

	entry = list_first_entry(src, struct isgx_enclave_page, load_list);
	enclave = entry->enclave;

	if (!isgx_pin_mm(enclave)) {
		while (!list_empty(src)) {
			entry = list_first_entry(src, struct isgx_enclave_page,
						 load_list);
			list_del(&entry->load_list);
			mutex_lock(&enclave->lock);
			isgx_free_epc_page(entry->epc_page, enclave,
					   ISGX_FREE_EREMOVE);
			entry->epc_page = NULL;
			entry->flags &= ~ISGX_ENCLAVE_PAGE_RESERVED;
			mutex_unlock(&enclave->lock);
		}

		kref_put(&enclave->refcount, isgx_enclave_release);
		return;
	}

	/* EBLOCK */

	list_for_each_entry_safe(entry, tmp, src, load_list) {
		mutex_lock(&enclave->lock);
		evma = isgx_find_vma(enclave, entry->addr);
		if (!evma) {
			list_del(&entry->load_list);
			isgx_free_epc_page(entry->epc_page, enclave,
					   ISGX_FREE_EREMOVE);
			entry->epc_page = NULL;
			entry->flags &= ~ISGX_ENCLAVE_PAGE_RESERVED;
			mutex_unlock(&enclave->lock);
			continue;
		}

		pages[cnt] = isgx_get_backing_page(enclave, entry, true);
		if (IS_ERR((void *) pages[cnt])) {
			list_del(&entry->load_list);
			list_add_tail(&entry->load_list, &enclave->load_list);
			entry->flags &= ~ISGX_ENCLAVE_PAGE_RESERVED;
			mutex_unlock(&enclave->lock);
			continue;
		}

		zap_vma_ptes(evma->vma, entry->addr, PAGE_SIZE);
		do_eblock(entry->epc_page);
		cnt++;
		mutex_unlock(&enclave->lock);
	}

	/* ETRACK */

	mutex_lock(&enclave->lock);
	do_etrack(enclave->secs_page.epc_page);
	mutex_unlock(&enclave->lock);

	/* EWB */

	mutex_lock(&enclave->lock);
	i = 0;

	while (!list_empty(src)) {
		entry = list_first_entry(src, struct isgx_enclave_page, load_list);
		list_del(&entry->load_list);

		evma = isgx_find_vma(enclave, entry->addr);
		if (evma) {
			ret = do_ewb(enclave, entry, pages[i]);
			BUG_ON(ret != 0 && ret != ISGX_NOT_TRACKED);
			/* Only kick out threads with an IPI if needed. */
			if (ret) {
				smp_call_function(isgx_ipi_cb, NULL, 1);
				BUG_ON(do_ewb(enclave, entry, pages[i]));
			}
			enclave->secs_child_cnt--;

			isgx_free_epc_page(entry->epc_page, enclave, 0);
		} else {
			isgx_free_epc_page(entry->epc_page, enclave,
					   ISGX_FREE_EREMOVE);
		}

		isgx_put_backing_page(pages[i++], evma != NULL);

		entry->epc_page = NULL;
		entry->flags &= ~ISGX_ENCLAVE_PAGE_RESERVED;
	}

	/* Allow SECS page eviction only when the enclave is initialized. */
	if (!enclave->secs_child_cnt &&
		(enclave->flags & ISGX_ENCLAVE_INITIALIZED)) {
		pages[cnt] = isgx_get_backing_page(enclave, &enclave->secs_page,
						   true);
		if (!IS_ERR((void *) pages[cnt])) {
			BUG_ON(do_ewb(enclave, &enclave->secs_page,
					pages[cnt]));
			enclave->flags |= ISGX_ENCLAVE_SECS_EVICTED;

			/* The secs page is not accounted (for unknown reason to
			 * me).
			 */
			isgx_free_epc_page(enclave->secs_page.epc_page, NULL, 0);
			isgx_put_backing_page(pages[cnt], true);

			enclave->secs_page.epc_page = NULL;
		}
	}

	mutex_unlock(&enclave->lock);
	BUG_ON(i != cnt);

	isgx_unpin_mm(enclave);
	kref_put(&enclave->refcount, isgx_enclave_release);
}

int kisgxswapd(void *p)
{
	LIST_HEAD(cluster);
	DEFINE_WAIT(wait);
	unsigned int nr_free;
	unsigned int nr_high;

	for ( ; ; ) {
		if (kthread_should_stop())
			break;

		spin_lock(&isgx_free_list_lock);
		nr_free = isgx_nr_free_epc_pages;
		nr_high = isgx_nr_high_epc_pages;
		spin_unlock(&isgx_free_list_lock);


		if (nr_free < nr_high) {
			isolate_cluster(&cluster, ISGX_NR_SWAP_CLUSTER_MAX);
			evict_cluster(&cluster, 0);

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

int isgx_page_cache_init(resource_size_t start, unsigned long size)
{
	unsigned long i;
	struct isgx_epc_page *new_epc_page, *entry;
	struct list_head *parser, *temp;

	for (i = 0; i < size; i += PAGE_SIZE) {
		new_epc_page = kzalloc(sizeof(struct isgx_epc_page), GFP_KERNEL);
		if (!new_epc_page)
			goto err_freelist;
		new_epc_page->pa = start + i;

		spin_lock(&isgx_free_list_lock);
		list_add_tail(&new_epc_page->free_list, &isgx_free_list);
		isgx_nr_total_epc_pages++;
		isgx_nr_free_epc_pages++;
		spin_unlock(&isgx_free_list_lock);
	}

	isgx_nr_high_epc_pages = 2 * isgx_nr_low_epc_pages;
	kisgxswapd_tsk = kthread_run(kisgxswapd, NULL, "kisgxswapd");

	return 0;
err_freelist:
	list_for_each_safe(parser, temp, &isgx_free_list) {
		spin_lock(&isgx_free_list_lock);
		entry = list_entry(parser, struct isgx_epc_page, free_list);
		list_del(&entry->free_list);
		spin_unlock(&isgx_free_list_lock);
		kfree(entry);
	}
	return -ENOMEM;
}

void isgx_page_cache_teardown(void)
{
	struct isgx_epc_page *entry;
	struct list_head *parser, *temp;

	if (kisgxswapd_tsk)
		kthread_stop(kisgxswapd_tsk);

	spin_lock(&isgx_free_list_lock);
	list_for_each_safe(parser, temp, &isgx_free_list) {
		entry = list_entry(parser, struct isgx_epc_page, free_list);
		list_del(&entry->free_list);
		kfree(entry);
	}
	spin_unlock(&isgx_free_list_lock);
}

static struct isgx_epc_page *isgx_alloc_epc_page_fast(void)
{
	struct isgx_epc_page *entry = NULL;

	spin_lock(&isgx_free_list_lock);

	if (!list_empty(&isgx_free_list)) {
		entry = list_first_entry(&isgx_free_list, struct isgx_epc_page,
					 free_list);
		list_del(&entry->free_list);
		isgx_nr_free_epc_pages--;
	}

	spin_unlock(&isgx_free_list_lock);

	return entry;
}

struct isgx_epc_page *isgx_alloc_epc_page(
	struct isgx_tgid_ctx *tgid_epc_cnt,
	unsigned int flags)
{
	LIST_HEAD(cluster);
	struct isgx_epc_page *entry;

	for ( ; ; ) {
		entry = isgx_alloc_epc_page_fast();
		if (entry) {
			if (tgid_epc_cnt)
				atomic_inc(&tgid_epc_cnt->epc_cnt);
			break;
		} else if (flags & ISGX_ALLOC_ATOMIC) {
			entry = ERR_PTR(-EBUSY);
			break;
		}

		if (signal_pending(current)) {
			entry = ERR_PTR(-ERESTARTSYS);
			break;
		}

		isolate_cluster(&cluster, ISGX_NR_SWAP_CLUSTER_MAX);
		evict_cluster(&cluster, flags);

		schedule();
	}

	if (isgx_nr_free_epc_pages < isgx_nr_low_epc_pages)
		wake_up(&kisgxswapd_waitq);

	return entry;
}

void isgx_free_epc_page(struct isgx_epc_page *entry,
			struct isgx_enclave *encl,
			unsigned int flags)
{
	BUG_ON(!entry);

	if (encl) {
		atomic_dec(&encl->tgid_ctx->epc_cnt);

		if (encl->flags & ISGX_ENCLAVE_SUSPEND)
			flags &= ~ISGX_FREE_EREMOVE;
	}

	if (flags & ISGX_FREE_EREMOVE)
		BUG_ON(isgx_eremove(entry));

	spin_lock(&isgx_free_list_lock);
	list_add(&entry->free_list, &isgx_free_list);
	isgx_nr_free_epc_pages++;
	spin_unlock(&isgx_free_list_lock);
}

/**
 * isgx_alloc_va_page() - Allocate a VA page (if necessary) for the enclave page
 * @enclave_page	the enclave page to be associated with the VA slot
 *
 * Allocates VA slot for the enclave page and fills in the appropriate fields.
 * Returns an error code on failure that can be either a POSIX error code or one
 * of the error codes defined in isgx_user.h.  Allocates a new VA page in the EPC
 * if there are no VA slots available.
 */
int isgx_alloc_va_page(struct isgx_enclave_page *enclave_page)
{
	struct isgx_va_page *va_page;
	struct isgx_epc_page *epc_page = NULL;
	unsigned int va_offset = PAGE_SIZE;
	void *vaddr;
	int ret;

	down_read(&isgx_va_pages_sem);
	list_for_each_entry(va_page, &isgx_va_pages, list) {
		va_offset = isgx_alloc_va_slot(va_page);
		if (va_offset < PAGE_SIZE)
			break;
	}
	up_read(&isgx_va_pages_sem);

	if (va_offset == PAGE_SIZE) {
		va_page = kzalloc(sizeof(*va_page), GFP_KERNEL);
		if (!va_page)
			return -ENOMEM;

		epc_page = isgx_alloc_epc_page(NULL, 0);
		if (IS_ERR(epc_page)) {
			kfree(va_page);
			return PTR_ERR(epc_page);
		}

		vaddr = isgx_get_epc_page(epc_page);
		BUG_ON(!vaddr);
		ret = __epa(vaddr);
		isgx_put_epc_page(vaddr);
		if (ret) {
			pr_err("isgx: EPA returned %d\n", ret);
			isgx_free_epc_page(epc_page, NULL, ISGX_FREE_EREMOVE);
			kfree(va_page);
			/* This probably a driver bug. Better to crash cleanly
			 * than let the failing driver to run.
			 */
			BUG();
		}

		va_page->epc_page = epc_page;
		va_offset = isgx_alloc_va_slot(va_page);
		BUG_ON(va_offset >= PAGE_SIZE);

		down_write(&isgx_va_pages_sem);
		list_add(&va_page->list, &isgx_va_pages);
		up_write(&isgx_va_pages_sem);
	}

	enclave_page->va_page = va_page;
	enclave_page->va_offset = va_offset;

	return 0;
}

/* isgx_free_va_page() - Conditionally removes a VA page from the EPC
 * @va_page		VA page to free
 *
 * It's possible a different thread allocated a slot in this VA page
 * while we were waiting for the semaphore.  Re-check the number of
 * used slots after acquiring the semaphore for writing.  Check the
 * list itself for validity to as a a different thread (or threads)
 * could have allocated and then freed (the last) slot while we were
 * waiting for the semaphore, creating a race to free the VA page.
 */
void isgx_free_va_page(struct isgx_va_page *va_page)
{
	down_write(&isgx_va_pages_sem);
	if (likely(atomic_read(&va_page->used) == 0 && !list_empty(&va_page->list))) {
		BUG_ON(find_first_bit(va_page->slots, ISGX_VA_SLOT_COUNT) != ISGX_VA_SLOT_COUNT);
		list_del_init(&va_page->list);
		isgx_free_epc_page(va_page->epc_page, NULL, ISGX_FREE_EREMOVE);
		kfree(va_page);
	}
	up_write(&isgx_va_pages_sem);
}
