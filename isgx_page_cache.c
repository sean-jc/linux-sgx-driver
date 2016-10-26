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

static struct isgx_tgid_ctx *ctx_to_age = NULL;
static struct isgx_tgid_ctx *ctx_to_iso = NULL;

unsigned int isgx_nr_total_epc_pages;
unsigned int isgx_nr_free_epc_pages;
unsigned int isgx_nr_low_epc_pages = ISGX_NR_LOW_EPC_PAGES_DEFAULT;
unsigned int isgx_nr_high_epc_pages;
struct task_struct *kisgxswapd_tsk;
static DECLARE_WAIT_QUEUE_HEAD(kisgxswapd_waitq);

/**
 * isgx_page_cache_ctx_released() - Update trackers on context release.
 * @ctx			Pointer to the context being released.
 *
 * If the context being released is either the next context to be aged
 * or processed then update the tracker accordingly.  Leave the tracker
 * invalid if the context is the last in the list; this is the easiest
 * way to handle the scenario where the context is the last man standing.
 * 
 */
void isgx_page_cache_ctx_released(struct isgx_tgid_ctx *ctx)
{
	if (ctx == ctx_to_age) {
		if (list_is_last(&ctx_to_age->list, &isgx_tgid_ctx_list))
			ctx_to_age = NULL;
		else
			ctx_to_age = list_next_entry(ctx_to_age, list);
	}
	if (ctx == ctx_to_iso) {
		if (list_is_last(&ctx_to_iso->list, &isgx_tgid_ctx_list))
			ctx_to_iso = NULL;
		else
			ctx_to_iso = list_next_entry(ctx_to_iso, list);
	}
}

/**
 * get_ctx_to_process() - Get the context whose turn it is to be aged/evicted.
 * @next				  Pointer to the associated tracker, e.g. &ctx_to_age.
 *
 * Get the next context to age/evict and update the associated tracker.  Reset
 * to the first context in the list if the tracker is invalid, e.g. the context
 * was released and was the last entry in the list.  Returns the context to
 * process, null if @isgx_tgid_ctx_list is empty.
 * 
 */
static inline struct isgx_tgid_ctx *get_ctx_to_process(struct isgx_tgid_ctx **next)
{
	struct isgx_tgid_ctx *ctx;

	mutex_lock(&isgx_tgid_ctx_mutex);
	
	if (*next == NULL && !list_empty(&isgx_tgid_ctx_list))
		*next = list_first_entry(&isgx_tgid_ctx_list, struct isgx_tgid_ctx, list);
	
	ctx = *next;
	if (ctx && !kref_get_unless_zero(&ctx->refcount)) {
		ctx = NULL;
	}
	if (*next)
	{
		if (list_is_last(&(*next)->list, &isgx_tgid_ctx_list))
			*next = list_first_entry(&isgx_tgid_ctx_list, struct isgx_tgid_ctx, list);
		else
			*next = list_next_entry(*next, list);
	}
	
	mutex_unlock(&isgx_tgid_ctx_mutex);

	return ctx;
}

/**
 * __age_epc_pages() - Age EPC for the 
 *
 */
static inline int __age_epc_pages(struct isgx_enclave *encl)
{
	int i, nr_to_scan = ISGX_NR_SWAP_CLUSTER_MAX;
	struct isgx_enclave_page *entry;

	LIST_HEAD(tmp);
	LIST_HEAD(new);
	LIST_HEAD(old);

	for (i = 0; i < nr_to_scan && !list_empty(&encl->active_epc); i++) {
		entry = list_first_entry(&encl->active_epc, struct isgx_enclave_page, epc_list);
		if (!isgx_test_and_clear_young(entry)) {
			entry->epc_age = -1;
			list_move_tail(&entry->epc_list, &new);
		} else {
			list_move_tail(&entry->epc_list, &tmp);
		}
	}

	/* Splice the processed entries back onto the tail of the active list */
	list_splice_tail_init(&tmp, &encl->active_epc);

	for (i = 0; i < nr_to_scan && !list_empty(&encl->inactive_epc); i++) {
		entry = list_first_entry(&encl->inactive_epc, struct isgx_enclave_page, epc_list);
		if (!isgx_test_and_clear_young(entry)) {
			if (--entry->epc_age < -1) {
				entry->epc_age = -1;
				list_move_tail(&entry->epc_list, &old);
			}
			else {
				list_move_tail(&entry->epc_list, &tmp);
			}
		} else {
			if (++entry->epc_age >= 1) {
				entry->epc_age = 1;
				list_move_tail(&entry->epc_list, &encl->active_epc);
			}
			else {
				list_move_tail(&entry->epc_list, &tmp);
			}
		}
	}

	/* Splice the processed-but-not-old inactive pages onto the tail of
	 * the inactive list, then splice the newly inactive pages onto the
	 * tail, and finally, splice the old inactive pages (inactive for a
	 * long time) onto the front of the list.  Using this approach, the
	 * truly ancient pages will be evicted first, while the pages that
	 * were just marked inactive will be evicted last.
	 */
	list_splice_tail(&tmp, &encl->inactive_epc);
	list_splice_tail(&new, &encl->inactive_epc);
	list_splice(&old, &encl->inactive_epc);

	return 0;
}

static void age_epc_pages(int nr_to_age)
{
	int i, nr_aged = 0;
	struct isgx_tgid_ctx *ctx;
	struct isgx_enclave *encl;

	for (i = 0; nr_aged < nr_to_age && i < atomic_read(&isgx_nr_pids); i++) {
		ctx = get_ctx_to_process(&ctx_to_age);
		if (!ctx)
			break;
			
		mutex_lock(&ctx->lock);

		if (!list_empty(&ctx->enclave_list)) {
			list_for_each_entry(encl, &ctx->enclave_list, enclave_list) {
				mutex_lock(&encl->lock);
				if (isgx_pin_mm(encl)) {
					nr_aged++;
					__age_epc_pages(encl);
					isgx_unpin_mm(encl);
				} 
				mutex_unlock(&encl->lock);
			}
		}

		mutex_unlock(&ctx->lock);

		kref_put(&ctx->refcount, release_tgid_ctx);
	}
}

static inline int __isolate_epc_pages(struct isgx_enclave *encl,
							   struct list_head *evict_list,
							   unsigned long nr_to_iso)
{
	int i, nr_isolated = 0, nr_to_scan = 2 * nr_to_iso;
	struct isgx_enclave_page *entry, *start = NULL;

	for (i = 0; i < nr_to_scan && nr_isolated < nr_to_iso; i++) {
		if (list_empty(&encl->inactive_epc))
			break;

		entry = list_first_entry(&encl->inactive_epc, struct isgx_enclave_page, epc_list);
		if (entry == start)
			break;

		if (!(entry->flags & ISGX_ENCLAVE_PAGE_RESERVED)) {
			nr_isolated++;
			entry->flags |= ISGX_ENCLAVE_PAGE_RESERVED;
			list_move_tail(&entry->epc_list, evict_list);
		} else {
			list_move_tail(&entry->epc_list, &encl->inactive_epc);

			if (!start)
				start = entry;
		}
	}

	return nr_isolated;
}

static int isolate_epc_pages(struct list_head *evict_list, unsigned long nr_to_iso)
{
	int i, nr_isolated;
	struct isgx_tgid_ctx *ctx;
	struct isgx_enclave *encl, *start_encl;

	for (i = 0; i < atomic_read(&isgx_nr_pids); i++) {
		ctx = get_ctx_to_process(&ctx_to_iso);
		if (!ctx)
			break;

		mutex_lock(&ctx->lock);

		start_encl = NULL;

		for ( ; ; ) {
			if (list_empty(&ctx->enclave_list))
				break;

			encl = list_first_entry(&ctx->enclave_list, struct isgx_enclave, enclave_list);
			if (encl == start_encl)
				break;

			if (!start_encl)
				start_encl = encl;

			list_move_tail(&encl->enclave_list, &ctx->enclave_list);

			/* Do not get the enclave's refcount while holding the context's
			 * lock, as invoking kref_put->isgx_enclave_release will cause
			 * self-inflicted deadlock.  On the plus side, because we have
			 * the context's lock it is safe to access the enclave without
			 * incrementing its ref count. 
			 */ 
			mutex_lock(&encl->lock);

			nr_isolated = __isolate_epc_pages(encl, evict_list, nr_to_iso);
			if (!nr_isolated && isgx_pin_mm(encl)) {
				__age_epc_pages(encl);
				isgx_unpin_mm(encl);
				
				nr_isolated = __isolate_epc_pages(encl, evict_list, nr_to_iso);
			}

			mutex_unlock(&encl->lock);

			/* If we isolated pages, then get a reference to the enclave,
			 * as dropping the context's lock will allow the enclave to be
			 * released.  Nuke the eviction list if the enclave is already
			 * being released, but still return immediately, as removing an
			 * enclave will have the same end result of freeing EPC pages.
			 */
			if (nr_isolated) {
				if (!kref_get_unless_zero(&encl->refcount)) {
					nr_isolated = 0;
					list_del_init(evict_list);
				}
				mutex_unlock(&ctx->lock);
				kref_put(&ctx->refcount, release_tgid_ctx);
				goto done;
			}
		}

		mutex_unlock(&ctx->lock);
		kref_put(&ctx->refcount, release_tgid_ctx);
	}
done:
	return nr_isolated;
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


static void evict_epc_pages(struct list_head *evict_list, unsigned int flags)
{
	struct isgx_enclave *enclave;
	struct isgx_enclave_page *entry;
	struct isgx_enclave_page *tmp;
	struct page *pages[ISGX_NR_SWAP_CLUSTER_MAX+1];
	struct vm_area_struct *vma;
	int cnt = 0;
	int i = 0;
	int ret;

	if (list_empty(evict_list))
		return;

	entry = list_first_entry(evict_list, struct isgx_enclave_page, epc_list);
	enclave = entry->enclave;

	mutex_lock(&enclave->lock);

	if (!isgx_pin_mm(enclave)) {
		while (!list_empty(evict_list)) {
			entry = list_first_entry(evict_list, struct isgx_enclave_page,
						 epc_list);
			list_del(&entry->epc_list);
			isgx_free_epc_page(entry->epc_page, enclave,
					   ISGX_FREE_EREMOVE);
			entry->epc_page = NULL;
			entry->flags &= ~ISGX_ENCLAVE_PAGE_RESERVED;
		}

		mutex_unlock(&enclave->lock);

		kref_put(&enclave->refcount, isgx_enclave_release);
		return;
	}

	/* EBLOCK */
	list_for_each_entry_safe(entry, tmp, evict_list, epc_list) {
		vma = isgx_find_vma(enclave, entry->addr);
		if (!vma) {
			list_del(&entry->epc_list);
			isgx_free_epc_page(entry->epc_page, enclave,
					   ISGX_FREE_EREMOVE);
			entry->epc_page = NULL;
			entry->flags &= ~ISGX_ENCLAVE_PAGE_RESERVED;
			continue;
		}

		pages[cnt] = isgx_get_backing_page(enclave, entry, true);
		if (IS_ERR((void *) pages[cnt])) {
			list_del(&entry->epc_list);
			list_add_tail(&entry->epc_list, &enclave->active_epc);
			entry->flags &= ~ISGX_ENCLAVE_PAGE_RESERVED;
			continue;
		}

		zap_vma_ptes(vma, entry->addr, PAGE_SIZE);
		do_eblock(entry->epc_page);
		cnt++;
	}

	if (!cnt)
		goto out;

	/* ETRACK */
	do_etrack(enclave->secs_page.epc_page);

	/* EWB */
	i = 0;
	while (!list_empty(evict_list)) {
		entry = list_first_entry(evict_list, struct isgx_enclave_page, epc_list);
		list_del(&entry->epc_list);

		vma = isgx_find_vma(enclave, entry->addr);
		if (vma) {
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

		isgx_put_backing_page(pages[i++], vma != NULL);

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
	BUG_ON(i != cnt);

out:
	isgx_unpin_mm(enclave);
	mutex_unlock(&enclave->lock);
	kref_put(&enclave->refcount, isgx_enclave_release);
}

int kisgxswapd(void *p)
{
	LIST_HEAD(evict_list);
	DEFINE_WAIT(wait);

	for ( ; ; ) {
		if (kthread_should_stop())
			break;

		if (isgx_nr_free_epc_pages < isgx_nr_high_epc_pages) {
			if (isolate_epc_pages(&evict_list, ISGX_NR_SWAP_CLUSTER_MAX))
				evict_epc_pages(&evict_list, 0);
			age_epc_pages(3);
			schedule();
		} 
		else {
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
	LIST_HEAD(evict_list);
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

		if (isolate_epc_pages(&evict_list, ISGX_NR_SWAP_CLUSTER_MAX))
			evict_epc_pages(&evict_list, flags);
		else
			schedule();
	}

	if (isgx_nr_free_epc_pages < isgx_nr_high_epc_pages)
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

void isgx_activate_epc_page(struct isgx_enclave_page *page,
						 	struct isgx_enclave *enclave)
{
	isgx_test_and_clear_young(page);

	page->epc_age = 0;
	list_add_tail(&page->epc_list, &enclave->active_epc);
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
