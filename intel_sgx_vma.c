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
#include <asm/mman.h>
#include <linux/delay.h>
#include <linux/file.h>
#include <linux/highmem.h>
#include <linux/ratelimit.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/hashtable.h>
#include <linux/shmem_fs.h>

static void sgx_vma_open(struct vm_area_struct *vma)
{
	struct sgx_encl *encl;

	/* Was vm_private_data nullified as a result of the previous fork? */
	encl = vma->vm_private_data;
	if (!encl)
		goto out_fork;

	/* Was the process forked? mm_struct changes when the process is
	 * forked.
	 */
	if (!encl->mm || encl->mm != vma->vm_mm) {
		goto out_fork;
	}

	atomic_inc(&encl->vma_cnt);

	kref_get(&encl->refcount);
	return;
out_fork:
	zap_vma_ptes(vma, vma->vm_start, vma->vm_end - vma->vm_start);
	vma->vm_private_data = NULL;
}

static void sgx_vma_close(struct vm_area_struct *vma)
{
	struct sgx_encl *encl = vma->vm_private_data;

	/* If process was forked, VMA is still there but
	 * vm_private_data is set to NULL.
	 */
	if (!encl)
		return;

	atomic_dec(&encl->vma_cnt);

	vma->vm_private_data = NULL;
	zap_vma_ptes(vma, vma->vm_start, vma->vm_end - vma->vm_start);

	kref_put(&encl->refcount, sgx_encl_release);
}

static int do_eldu(struct sgx_encl *encl,
		   struct sgx_encl_page *encl_page,
		   struct sgx_epc_page *epc_page,
		   struct page *backing,
		   bool is_secs)
{
	struct sgx_page_info pginfo;
	void *secs_ptr = NULL;
	void *epc_ptr;
	void *va_ptr;
	int ret;

	pginfo.srcpge = (unsigned long)kmap_atomic(backing);
	if (!is_secs)
		secs_ptr = sgx_get_epc_page(encl->secs_page.epc_page);
	pginfo.secs = (unsigned long)secs_ptr;

	epc_ptr = sgx_get_epc_page(epc_page);
	va_ptr = sgx_get_epc_page(encl_page->va_page->epc_page);

	pginfo.linaddr = is_secs ? 0 : encl_page->addr;
	pginfo.pcmd = (unsigned long)&encl_page->pcmd;

	ret = __eldu((unsigned long)&pginfo,
		     (unsigned long)epc_ptr,
		     (unsigned long)va_ptr +
		     encl_page->va_offset);

	sgx_put_epc_page(va_ptr);
	sgx_put_epc_page(epc_ptr);

	if (!is_secs)
		sgx_put_epc_page(secs_ptr);

	kunmap_atomic((void *)(unsigned long)pginfo.srcpge);
	WARN_ON(ret);
	if (ret)
		return -EFAULT;

	return 0;
}

static struct sgx_encl_page *sgx_vma_do_fault(struct vm_area_struct *vma,
					      unsigned long addr, int reserve)
{
	struct sgx_encl *encl = vma->vm_private_data;
	struct sgx_encl_page *entry;
	struct sgx_epc_page *epc_page;
	struct sgx_epc_page *secs_epc_page = NULL;
	struct page *backing;
	unsigned int free_flags = SGX_FREE_SKIP_EREMOVE;
	int rc;

	/* If process was forked, VMA is still there but vm_private_data is set
	 * to NULL.
	 */
	if (!encl)
		return ERR_PTR(-EFAULT);

	entry = sgx_encl_find_page(encl, addr);
	if (!entry)
		return ERR_PTR(-EFAULT);

	epc_page = sgx_alloc_page(encl->tgid_ctx, SGX_ALLOC_ATOMIC);
	if (IS_ERR(epc_page))
		/* reinterpret the type as we return an error */
		return (struct sgx_encl_page *)epc_page;

	mutex_lock(&encl->lock);

	if (!atomic_read(&encl->vma_cnt)) {
		entry = ERR_PTR(-EFAULT);
		goto out;
	}

	if (!(encl->flags & SGX_ENCL_INITIALIZED)) {
		sgx_dbg(encl, "cannot fault, unitialized\n");
		entry = ERR_PTR(-EFAULT);
		goto out;
	}

	if (reserve && (entry->flags & SGX_ENCL_PAGE_RESERVED)) {
		sgx_dbg(encl, "cannot fault, 0x%lx is reserved\n",
			entry->addr);
		entry = ERR_PTR(-EBUSY);
		goto out;
	}

	/* Legal race condition, page is already faulted. */
	if (entry->epc_page) {
		if (reserve)
			entry->flags |= SGX_ENCL_PAGE_RESERVED;
		goto out;
	}

	/* If SECS is evicted then reload it first */
	if (encl->flags & SGX_ENCL_SECS_EVICTED) {
		/* Note that calling sgx_alloc_page while holding encl->lock is
		 * normally illegal as it leads to deadlocks, but is ok in this
		 * case as SGX_ALLOC_ATOMIC will prevent sgx_alloc_page from
		 * going into the problematic flows.
		 */
		secs_epc_page = sgx_alloc_page(encl->tgid_ctx, SGX_ALLOC_ATOMIC);
		if (IS_ERR(secs_epc_page)) {
			entry = (void *)secs_epc_page;
			secs_epc_page = NULL;
			goto out;
		}

		backing = sgx_get_backing(encl, &encl->secs_page);
		if (IS_ERR(backing)) {
			entry = (void *)backing;
			goto out;
		}

		rc = do_eldu(encl, &encl->secs_page, secs_epc_page,
			     backing, true /* is_secs */);
		sgx_put_backing(backing, 0);
		if (rc)
			goto out;

		encl->secs_page.epc_page = secs_epc_page;
		encl->flags &= ~SGX_ENCL_SECS_EVICTED;

		/* Do not free */
		secs_epc_page = NULL;
	}

	backing = sgx_get_backing(encl, entry);
	if (IS_ERR(backing)) {
		entry = (void *)backing;
		goto out;
	}

	do_eldu(encl, entry, epc_page, backing, false /* is_secs */);
	rc = vm_insert_pfn(vma, entry->addr, PFN_DOWN(epc_page->pa));
	sgx_put_backing(backing, 0);

	if (rc) {
		free_flags = 0;
		goto out;
	}

	encl->secs_child_cnt++;

	entry->epc_page = epc_page;

	if (reserve)
		entry->flags |= SGX_ENCL_PAGE_RESERVED;

	/* Do not free */
	epc_page = NULL;

	list_add_tail(&entry->load_list, &encl->load_list);
out:
	mutex_unlock(&encl->lock);
	if (encl->flags & SGX_ENCL_SUSPEND)
		free_flags |= SGX_FREE_SKIP_EREMOVE;
	if (epc_page)
		sgx_free_page(epc_page, encl, free_flags);
	if (secs_epc_page)
		sgx_free_page(secs_epc_page, encl, SGX_FREE_SKIP_EREMOVE);
	return entry;
}

static int sgx_vma_fault(struct vm_area_struct *vma, struct vm_fault *vmf)
{
	unsigned long addr = (unsigned long)vmf->virtual_address;
	struct sgx_encl_page *entry;

	entry = sgx_vma_do_fault(vma, addr, 0);

	if (!IS_ERR(entry) || PTR_ERR(entry) == -EBUSY)
		return VM_FAULT_NOPAGE;
	else
		return VM_FAULT_SIGBUS;
}

static inline int sgx_vma_access_word(struct sgx_encl *encl,
				      unsigned long addr,
				      void *buf,
				      int len,
				      int write,
				      struct sgx_encl_page *encl_page,
				      int i)
{
	char data[sizeof(unsigned long)];
	int align, cnt, offset;
	void *vaddr;
	int ret;

	offset = ((addr + i) & (PAGE_SIZE - 1)) & ~(sizeof(unsigned long) - 1);
	align = (addr + i) & (sizeof(unsigned long) - 1);
	cnt = sizeof(unsigned long) - align;
	cnt = min(cnt, len - i);

	if (write) {
		if (encl_page->flags & SGX_ENCL_PAGE_TCS &&
		    (offset < 8 || (offset + (len - i)) > 16))
			return -ECANCELED;

		if (align || (cnt != sizeof(unsigned long))) {
			vaddr = sgx_get_epc_page(encl_page->epc_page);
			ret = __edbgrd((void *)((unsigned long)vaddr + offset),
				       (unsigned long *)data);
			sgx_put_epc_page(vaddr);
			if (ret) {
				sgx_dbg(encl, "EDBGRD returned %d\n", ret);
				return -EFAULT;
			}
		}

		memcpy(data + align, buf + i, cnt);
		vaddr = sgx_get_epc_page(encl_page->epc_page);
		ret = __edbgwr((void *)((unsigned long)vaddr + offset),
			       (unsigned long *)data);
		sgx_put_epc_page(vaddr);
		if (ret) {
			sgx_dbg(encl, "EDBGWR returned %d\n", ret);
			return -EFAULT;
		}
	} else {
		if (encl_page->flags & SGX_ENCL_PAGE_TCS &&
		    (offset + (len - i)) > 72)
			return -ECANCELED;

		vaddr = sgx_get_epc_page(encl_page->epc_page);
		ret = __edbgrd((void *)((unsigned long)vaddr + offset),
			       (unsigned long *)data);
		sgx_put_epc_page(vaddr);
		if (ret) {
			sgx_dbg(encl, "EDBGRD returned %d\n", ret);
			return -EFAULT;
		}

		memcpy(buf + i, data + align, cnt);
	}

	return cnt;
}

static int sgx_vma_access(struct vm_area_struct *vma, unsigned long addr,
			  void *buf, int len, int write)
{
	struct sgx_encl *encl = vma->vm_private_data;
	struct sgx_encl_page *entry = NULL;
	const char *op_str = write ? "EDBGWR" : "EDBGRD";
	int ret = 0;
	int i;

	/* If process was forked, VMA is still there but vm_private_data is set
	 * to NULL.
	 */
	if (!encl)
		return -EFAULT;

	if (!(encl->flags & SGX_ENCL_DEBUG) ||
	    !(encl->flags & SGX_ENCL_INITIALIZED) ||
	    (encl->flags & SGX_ENCL_SUSPEND))
		return -EFAULT;

	sgx_dbg(encl, "%s addr=0x%lx, len=%d\n", op_str, addr, len);

	for (i = 0; i < len; i += ret) {
		if (!entry || !((addr + i) & (PAGE_SIZE - 1))) {
			if (entry)
				entry->flags &= ~SGX_ENCL_PAGE_RESERVED;

			do {
				entry = sgx_vma_do_fault(
					vma, (addr + i) & PAGE_MASK, true);
			} while (entry == ERR_PTR(-EBUSY));

			if (IS_ERR(entry)) {
				ret = PTR_ERR(entry);
				entry = NULL;
				break;
			}
		}

		/* No locks are needed because used fields are immutable after
		 * intialization.
		 */
		ret = sgx_vma_access_word(encl, addr, buf, len, write,
					  entry, i);
		if (ret < 0)
			break;
	}

	if (entry)
		entry->flags &= ~SGX_ENCL_PAGE_RESERVED;

	return (ret < 0 && ret != -ECANCELED) ? ret : i;
}

const struct vm_operations_struct sgx_vm_ops = {
	.close = sgx_vma_close,
	.open = sgx_vma_open,
	.fault = sgx_vma_fault,
	.access = sgx_vma_access,
};
