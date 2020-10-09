// SPDX-License-Identifier: GPL-2.0-only
/*
 * mm/truncate.c - code for taking down pages from address_spaces
 *
 * Copyright (C) 2002, Linus Torvalds
 *
 * 10Sep2002	Andrew Morton
 *		Initial version.
 */

#include <linux/kernel.h>
#include <linux/backing-dev.h>
#include <linux/dax.h>
#include <linux/gfp.h>
#include <linux/mm.h>
#include <linux/swap.h>
#include <linux/export.h>
#include <linux/pagemap.h>
#include <linux/highmem.h>
#include <linux/pagevec.h>
#include <linux/task_io_accounting_ops.h>
#include <linux/buffer_head.h>	/* grr. try_to_release_page,
				   do_invalidatepage */
#include <linux/shmem_fs.h>
#include <linux/cleancache.h>
#include <linux/rmap.h>
#include "internal.h"

/*
 * Regular page slots are stabilized by the page lock even without the tree
 * itself locked.  These unlocked entries need verification under the tree
 * lock.
 */
static inline void __clear_shadow_entry(struct address_space *mapping,
				pgoff_t index, void *entry)
{
	XA_STATE(xas, &mapping->i_pages, index);

	xas_set_update(&xas, workingset_update_node);
	if (xas_load(&xas) != entry)
		return;
	xas_store(&xas, NULL);
}

static void clear_shadow_entry(struct address_space *mapping, pgoff_t index,
			       void *entry)
{
	xa_lock_irq(&mapping->i_pages);
	__clear_shadow_entry(mapping, index, entry);
	xa_unlock_irq(&mapping->i_pages);
}

/*
 * Unconditionally remove exceptional entries. Usually called from truncate
 * path. Note that the pagevec may be altered by this function by removing
 * exceptional entries similar to what pagevec_remove_exceptionals does.
 */
static void truncate_exceptional_pvec_entries(struct address_space *mapping,
				struct pagevec *pvec, pgoff_t *indices)
{
	int i, j;
	bool dax;

	/* Handled by shmem itself */
	if (shmem_mapping(mapping))
		return;

	for (j = 0; j < pagevec_count(pvec); j++)
		if (xa_is_value(pvec->pages[j]))
			break;

	if (j == pagevec_count(pvec))
		return;

	dax = dax_mapping(mapping);
	if (!dax)
		xa_lock_irq(&mapping->i_pages);

	for (i = j; i < pagevec_count(pvec); i++) {
		struct page *page = pvec->pages[i];
		pgoff_t index = indices[i];

		if (!xa_is_value(page)) {
			pvec->pages[j++] = page;
			continue;
		}

		if (unlikely(dax)) {
			dax_delete_mapping_entry(mapping, index);
			continue;
		}

		__clear_shadow_entry(mapping, index, page);
	}

	if (!dax)
		xa_unlock_irq(&mapping->i_pages);
	pvec->nr = j;
}

/*
 * Invalidate exceptional entry if easily possible. This handles exceptional
 * entries for invalidate_inode_pages().
 */
static int invalidate_exceptional_entry(struct address_space *mapping,
					pgoff_t index, void *entry)
{
	/* Handled by shmem itself, or for DAX we do nothing. */
	if (shmem_mapping(mapping) || dax_mapping(mapping))
		return 1;
	clear_shadow_entry(mapping, index, entry);
	return 1;
}

/*
 * Invalidate exceptional entry if clean. This handles exceptional entries for
 * invalidate_inode_pages2() so for DAX it evicts only clean entries.
 */
static int invalidate_exceptional_entry2(struct address_space *mapping,
					 pgoff_t index, void *entry)
{
	/* Handled by shmem itself */
	if (shmem_mapping(mapping))
		return 1;
	if (dax_mapping(mapping))
		return dax_invalidate_mapping_entry_sync(mapping, index);
	clear_shadow_entry(mapping, index, entry);
	return 1;
}

/**
 * do_invalidatepage - invalidate part or all of a page
 * @page: the page which is affected
 * @offset: start of the range to invalidate
 * @length: length of the range to invalidate
 *
 * do_invalidatepage() is called when all or part of the page has become
 * invalidated by a truncate operation.
 *
 * do_invalidatepage() does not have to release all buffers, but it must
 * ensure that no dirty buffer is left outside @offset and that no I/O
 * is underway against any of the blocks which are outside the truncation
 * point.  Because the caller is about to free (and possibly reuse) those
 * blocks on-disk.
 */
void do_invalidatepage(struct page *page, unsigned int offset,
		       unsigned int length)
{
	void (*invalidatepage)(struct page *, unsigned int, unsigned int);

	invalidatepage = page->mapping->a_ops->invalidatepage;
#ifdef CONFIG_BLOCK
	if (!invalidatepage)
		invalidatepage = block_invalidatepage;
#endif
	if (invalidatepage)
		(*invalidatepage)(page, offset, length);
}

/*
 * If truncate cannot remove the fs-private metadata from the page, the page
 * becomes orphaned.  It will be left on the LRU and may even be mapped into
 * user pagetables if we're racing with filemap_fault().
 *
 * We need to bail out if page->mapping is no longer equal to the original
 * mapping.  This happens a) when the VM reclaimed the page while we waited on
 * its lock, b) when a concurrent invalidate_mapping_pages got there first and
 * c) when tmpfs swizzles a page between a tmpfs inode and swapper_space.
 */
static void
truncate_cleanup_page(struct address_space *mapping, struct page *page)
{
	if (page_mapped(page)) {
		unsigned int nr = thp_nr_pages(page);
		unmap_mapping_pages(mapping, page->index, nr, false);
	}

	if (page_has_private(page))
		do_invalidatepage(page, 0, thp_size(page));

	/*
	 * Some filesystems seem to re-dirty the page even after
	 * the VM has canceled the dirty bit (eg ext3 journaling).
	 * Hence dirty accounting check is placed after invalidation.
	 */
	cancel_dirty_page(page);
	ClearPageMappedToDisk(page);
}

/*
 * This is for invalidate_mapping_pages().  That function can be called at
 * any time, and is not supposed to throw away dirty pages.  But pages can
 * be marked dirty at any time too, so use remove_mapping which safely
 * discards clean, unused pages.
 *
 * Returns non-zero if the page was successfully invalidated.
 */
static int
invalidate_complete_page(struct address_space *mapping, struct page *page)
{
	int ret;

	if (page->mapping != mapping)
		return 0;

	if (page_has_private(page) && !try_to_release_page(page, 0))
		return 0;

	ret = remove_mapping(mapping, page);

	return ret;
}

int truncate_inode_page(struct address_space *mapping, struct page *page)
{
	VM_BUG_ON_PAGE(PageTail(page), page);

	if (page->mapping != mapping)
		return -EIO;

	truncate_cleanup_page(mapping, page);
	delete_from_page_cache(page);
	return 0;
}

static unsigned int greatest_pow_of_two_multiplier(unsigned int num)
{
	if (num & 1)
		return 0;
	return min_t(unsigned int, ilog2(num),
		ilog2(num - rounddown_pow_of_two(num)));
}

/*
 * Handle partial (transparent) pages.  If the page is entirely within
 * the range, we discard it.  If not, we split the page if it's a THP
 * and zero the part of the page that's within the [start, end] range.
 * split_page_range() will discard any of the subpages which now lie
 * beyond i_size, and the caller will discard pages which lie within a
 * newly created hole.
 *
 * Return: The index after the current page.
 */
pgoff_t truncate_inode_partial_page(struct address_space *mapping,
		struct page *page, loff_t start, loff_t end)
{
	loff_t pos = page_offset(page);
	pgoff_t next_index = page->index + thp_nr_pages(page);
	unsigned int origin_offset, offset, length, remaining;
	unsigned int new_order = thp_order(page);


	if (pos < start)
		offset = start - pos;
	else
		offset = 0;
	origin_offset = offset;
	length = thp_size(page);
	if (pos + length <= (u64)end)
		length = length - offset;
	else
		length = end + 1 - pos - offset;
	remaining = thp_size(page) - offset - length;

	wait_on_page_writeback(page);
	if (length == thp_size(page))
		goto truncate;

	cleancache_invalidate_page(page->mapping, page);
	if (page_has_private(page))
		do_invalidatepage(page, offset, length);
	if (!PageTransHuge(page))
		goto zero;
	page += offset / PAGE_SIZE;

	/*
	 * Find the greatest common power of two multiplier of the non-zero
	 * offset, length, and remaining as the new order. So we can truncate
	 * a subpage as large as possible.
	 */
	if (offset)
		new_order = greatest_pow_of_two_multiplier(offset / PAGE_SIZE);
	if (length)
		new_order = min_t(unsigned int, new_order,
			greatest_pow_of_two_multiplier(length / PAGE_SIZE));
	if (remaining)
		new_order = min_t(unsigned int, new_order,
			greatest_pow_of_two_multiplier(remaining / PAGE_SIZE));

	/* order-1 THP not supported, downgrade to order-0 */
	if (new_order == 1)
		new_order = 0;

	if (split_huge_page_to_list_to_order(page, NULL, new_order) < 0) {
		page -= offset / PAGE_SIZE;
		goto zero;
	}
	next_index = page->index + 1;
	offset %= PAGE_SIZE;
	if (offset == 0 && length >= PAGE_SIZE)
		goto truncate;
	length = PAGE_SIZE - offset;
zero:
	zero_user(page, offset, length);
	goto out;
truncate:
	truncate_inode_page(mapping, page);
out:
	unlock_page(page);
	put_page(page);
	return next_index;
}

/*
 * Used to get rid of pages on hardware memory corruption.
 */
int generic_error_remove_page(struct address_space *mapping, struct page *page)
{
	if (!mapping)
		return -EINVAL;
	/*
	 * Only punch for normal data pages for now.
	 * Handling other types like directories would need more auditing.
	 */
	if (!S_ISREG(mapping->host->i_mode))
		return -EIO;
	return truncate_inode_page(mapping, page);
}
EXPORT_SYMBOL(generic_error_remove_page);

/*
 * Safely invalidate one page from its pagecache mapping.
 * It only drops clean, unused pages. The page must be locked.
 *
 * Returns 1 if the page is successfully invalidated, otherwise 0.
 */
int invalidate_inode_page(struct page *page)
{
	struct address_space *mapping = page_mapping(page);
	if (!mapping)
		return 0;
	if (PageDirty(page) || PageWriteback(page))
		return 0;
	if (page_mapped(page))
		return 0;
	return invalidate_complete_page(mapping, page);
}

/**
 * truncate_inode_pages_range - truncate range of pages specified by start & end byte offsets
 * @mapping: mapping to truncate
 * @lstart: offset from which to truncate
 * @lend: offset to which to truncate (inclusive)
 *
 * Truncate the page cache, removing the pages that are between
 * specified offsets (and zeroing out partial pages
 * if lstart or lend + 1 is not page aligned).
 *
 * Truncate takes two passes - the first pass is nonblocking.  It will not
 * block on page locks and it will not block on writeback.  The second pass
 * will wait.  This is to prevent as much IO as possible in the affected region.
 * The first pass will remove most pages, so the search cost of the second pass
 * is low.
 *
 * Note that since ->invalidatepage() accepts range to invalidate
 * truncate_inode_pages_range is able to handle cases where lend + 1 is not
 * page aligned properly.
 */
void truncate_inode_pages_range(struct address_space *mapping,
				loff_t lstart, loff_t lend)
{
	pgoff_t start, end;
	struct pagevec	pvec;
	pgoff_t		indices[PAGEVEC_SIZE];
	pgoff_t		index;
	int		i;
	struct page *	page;

	if (mapping_empty(mapping))
		goto out;

	start = lstart >> PAGE_SHIFT;
	page = find_lock_head(mapping, start);
	if (page)
		start = truncate_inode_partial_page(mapping, page, lstart,
							lend);

	/* 'end' includes a partial page */
	end = lend / PAGE_SIZE;

	pagevec_init(&pvec);
	index = start;
	while (index < end && find_lock_entries(mapping, index, end - 1,
			&pvec, indices)) {
		index = indices[pagevec_count(&pvec) - 1] + 1;
		truncate_exceptional_pvec_entries(mapping, &pvec, indices);
		for (i = 0; i < pagevec_count(&pvec); i++)
			truncate_cleanup_page(mapping, pvec.pages[i]);
		delete_from_page_cache_batch(mapping, &pvec);
		for (i = 0; i < pagevec_count(&pvec); i++)
			unlock_page(pvec.pages[i]);
		pagevec_release(&pvec);
		cond_resched();
	}

	index = start;
	while (index <= end) {
		cond_resched();

		if (!find_get_entries(mapping, index, end, &pvec, indices)) {
			/* If all gone from start onwards, we're done */
			if (index == start)
				break;
			/* Otherwise restart to make sure all gone */
			index = start;
			continue;
		}

		for (i = 0; i < pagevec_count(&pvec); i++) {
			page = pvec.pages[i];
			if (xa_is_value(page))
				continue;

			lock_page(page);
			index = truncate_inode_partial_page(mapping, page,
							lstart, lend);
			/* Couldn't split a THP? */
			if (index > end)
				end = indices[i] - 1;
		}
		index = indices[i - 1] + 1;
		truncate_exceptional_pvec_entries(mapping, &pvec, indices);
		pagevec_reinit(&pvec);
	}

out:
	cleancache_invalidate_inode(mapping);
}
EXPORT_SYMBOL(truncate_inode_pages_range);

/**
 * truncate_inode_pages - truncate *all* the pages from an offset
 * @mapping: mapping to truncate
 * @lstart: offset from which to truncate
 *
 * Called under (and serialised by) inode->i_mutex.
 *
 * Note: When this function returns, there can be a page in the process of
 * deletion (inside __delete_from_page_cache()) in the specified range.  Thus
 * mapping->nrpages can be non-zero when this function returns even after
 * truncation of the whole mapping.
 */
void truncate_inode_pages(struct address_space *mapping, loff_t lstart)
{
	truncate_inode_pages_range(mapping, lstart, (loff_t)-1);
}
EXPORT_SYMBOL(truncate_inode_pages);

/**
 * truncate_inode_pages_final - truncate *all* pages before inode dies
 * @mapping: mapping to truncate
 *
 * Called under (and serialized by) inode->i_mutex.
 *
 * Filesystems have to use this in the .evict_inode path to inform the
 * VM that this is the final truncate and the inode is going away.
 */
void truncate_inode_pages_final(struct address_space *mapping)
{
	/*
	 * Page reclaim can not participate in regular inode lifetime
	 * management (can't call iput()) and thus can race with the
	 * inode teardown.  Tell it when the address space is exiting,
	 * so that it does not install eviction information after the
	 * final truncate has begun.
	 */
	mapping_set_exiting(mapping);

	if (!mapping_empty(mapping)) {
		/*
		 * As truncation uses a lockless tree lookup, cycle
		 * the tree lock to make sure any ongoing tree
		 * modification that does not see AS_EXITING is
		 * completed before starting the final truncate.
		 */
		xa_lock_irq(&mapping->i_pages);
		xa_unlock_irq(&mapping->i_pages);
	}

	/*
	 * Cleancache needs notification even if there are no pages or shadow
	 * entries.
	 */
	truncate_inode_pages(mapping, 0);
}
EXPORT_SYMBOL(truncate_inode_pages_final);

static unsigned long __invalidate_mapping_pages(struct address_space *mapping,
		pgoff_t start, pgoff_t end, unsigned long *nr_pagevec)
{
	pgoff_t indices[PAGEVEC_SIZE];
	struct pagevec pvec;
	pgoff_t index = start;
	unsigned long ret;
	unsigned long count = 0;
	int i;

	pagevec_init(&pvec);
	while (find_lock_entries(mapping, index, end, &pvec, indices)) {
		for (i = 0; i < pagevec_count(&pvec); i++) {
			struct page *page = pvec.pages[i];

			/* We rely upon deletion not changing page->index */
			index = indices[i];

			if (xa_is_value(page)) {
				invalidate_exceptional_entry(mapping, index,
							     page);
				continue;
			}
			index += thp_nr_pages(page) - 1;

			ret = invalidate_inode_page(page);
			unlock_page(page);
			/*
			 * Invalidation is a hint that the page is no longer
			 * of interest and try to speed up its reclaim.
			 */
			if (!ret) {
				deactivate_file_page(page);
				/* It is likely on the pagevec of a remote CPU */
				if (nr_pagevec)
					(*nr_pagevec)++;
			}
			count += ret;
		}
		pagevec_remove_exceptionals(&pvec);
		pagevec_release(&pvec);
		cond_resched();
		index++;
	}
	return count;
}

/**
 * invalidate_mapping_pages - Invalidate all the unlocked pages of one inode
 * @mapping: the address_space which holds the pages to invalidate
 * @start: the offset 'from' which to invalidate
 * @end: the offset 'to' which to invalidate (inclusive)
 *
 * This function only removes the unlocked pages, if you want to
 * remove all the pages of one inode, you must call truncate_inode_pages.
 *
 * invalidate_mapping_pages() will not block on IO activity. It will not
 * invalidate pages which are dirty, locked, under writeback or mapped into
 * pagetables.
 *
 * Return: the number of the pages that were invalidated
 */
unsigned long invalidate_mapping_pages(struct address_space *mapping,
		pgoff_t start, pgoff_t end)
{
	return __invalidate_mapping_pages(mapping, start, end, NULL);
}
EXPORT_SYMBOL(invalidate_mapping_pages);

/**
 * invalidate_mapping_pagevec - Invalidate all the unlocked pages of one inode
 * @mapping: the address_space which holds the pages to invalidate
 * @start: the offset 'from' which to invalidate
 * @end: the offset 'to' which to invalidate (inclusive)
 * @nr_pagevec: invalidate failed page number for caller
 *
 * This helper is similar to invalidate_mapping_pages(), except that it accounts
 * for pages that are likely on a pagevec and counts them in @nr_pagevec, which
 * will be used by the caller.
 */
void invalidate_mapping_pagevec(struct address_space *mapping,
		pgoff_t start, pgoff_t end, unsigned long *nr_pagevec)
{
	__invalidate_mapping_pages(mapping, start, end, nr_pagevec);
}

/*
 * This is like invalidate_complete_page(), except it ignores the page's
 * refcount.  We do this because invalidate_inode_pages2() needs stronger
 * invalidation guarantees, and cannot afford to leave pages behind because
 * shrink_page_list() has a temp ref on them, or because they're transiently
 * sitting in the lru_cache_add() pagevecs.
 */
static int
invalidate_complete_page2(struct address_space *mapping, struct page *page)
{
	unsigned long flags;

	if (page->mapping != mapping)
		return 0;

	if (page_has_private(page) && !try_to_release_page(page, GFP_KERNEL))
		return 0;

	xa_lock_irqsave(&mapping->i_pages, flags);
	if (PageDirty(page))
		goto failed;

	BUG_ON(page_has_private(page));
	__delete_from_page_cache(page, NULL);
	xa_unlock_irqrestore(&mapping->i_pages, flags);

	page_cache_free_page(mapping, page);
	return 1;
failed:
	xa_unlock_irqrestore(&mapping->i_pages, flags);
	return 0;
}

static int do_launder_page(struct address_space *mapping, struct page *page)
{
	if (!PageDirty(page))
		return 0;
	if (page->mapping != mapping || mapping->a_ops->launder_page == NULL)
		return 0;
	return mapping->a_ops->launder_page(page);
}

/**
 * invalidate_inode_pages2_range - remove range of pages from an address_space
 * @mapping: the address_space
 * @start: the page offset 'from' which to invalidate
 * @end: the page offset 'to' which to invalidate (inclusive)
 *
 * Any pages which are found to be mapped into pagetables are unmapped prior to
 * invalidation.
 *
 * Return: -EBUSY if any pages could not be invalidated.
 */
int invalidate_inode_pages2_range(struct address_space *mapping,
				  pgoff_t start, pgoff_t end)
{
	pgoff_t indices[PAGEVEC_SIZE];
	struct pagevec pvec;
	pgoff_t index;
	int i;
	int ret = 0;
	int ret2 = 0;
	int did_range_unmap = 0;

	if (mapping_empty(mapping))
		goto out;

	pagevec_init(&pvec);
	index = start;
	while (find_get_entries(mapping, index, end, &pvec, indices)) {
		for (i = 0; i < pagevec_count(&pvec); i++) {
			struct page *page = pvec.pages[i];
			pgoff_t count;

			/* We rely upon deletion not changing page->index */
			index = indices[i];

			if (xa_is_value(page)) {
				if (!invalidate_exceptional_entry2(mapping,
								   index, page))
					ret = -EBUSY;
				continue;
			}

			lock_page(page);
			if (page->mapping != mapping) {
				unlock_page(page);
				continue;
			}
			wait_on_page_writeback(page);
			count = thp_nr_pages(page);
			index = page->index + count - 1;
			if (page_mapped(page)) {
				if (!did_range_unmap) {
					/* Zap the rest of the file */
					count = max(count,
							end - page->index + 1);
					did_range_unmap = 1;
				}
				unmap_mapping_pages(mapping, page->index,
						count, false);
			}
			BUG_ON(page_mapped(page));
			ret2 = do_launder_page(mapping, page);
			if (ret2 == 0) {
				if (!invalidate_complete_page2(mapping, page))
					ret2 = -EBUSY;
			}
			if (ret2 < 0)
				ret = ret2;
			unlock_page(page);
		}
		pagevec_remove_exceptionals(&pvec);
		pagevec_release(&pvec);
		cond_resched();
		index++;
	}
	/*
	 * For DAX we invalidate page tables after invalidating page cache.  We
	 * could invalidate page tables while invalidating each entry however
	 * that would be expensive. And doing range unmapping before doesn't
	 * work as we have no cheap way to find whether page cache entry didn't
	 * get remapped later.
	 */
	if (dax_mapping(mapping)) {
		unmap_mapping_pages(mapping, start, end - start + 1, false);
	}
out:
	cleancache_invalidate_inode(mapping);
	return ret;
}
EXPORT_SYMBOL_GPL(invalidate_inode_pages2_range);

/**
 * invalidate_inode_pages2 - remove all pages from an address_space
 * @mapping: the address_space
 *
 * Any pages which are found to be mapped into pagetables are unmapped prior to
 * invalidation.
 *
 * Return: -EBUSY if any pages could not be invalidated.
 */
int invalidate_inode_pages2(struct address_space *mapping)
{
	return invalidate_inode_pages2_range(mapping, 0, -1);
}
EXPORT_SYMBOL_GPL(invalidate_inode_pages2);

/**
 * truncate_pagecache - unmap and remove pagecache that has been truncated
 * @inode: inode
 * @newsize: new file size
 *
 * inode's new i_size must already be written before truncate_pagecache
 * is called.
 *
 * This function should typically be called before the filesystem
 * releases resources associated with the freed range (eg. deallocates
 * blocks). This way, pagecache will always stay logically coherent
 * with on-disk format, and the filesystem would not have to deal with
 * situations such as writepage being called for a page that has already
 * had its underlying blocks deallocated.
 */
void truncate_pagecache(struct inode *inode, loff_t newsize)
{
	struct address_space *mapping = inode->i_mapping;
	loff_t holebegin = round_up(newsize, PAGE_SIZE);

	/*
	 * unmap_mapping_range is called twice, first simply for
	 * efficiency so that truncate_inode_pages does fewer
	 * single-page unmaps.  However after this first call, and
	 * before truncate_inode_pages finishes, it is possible for
	 * private pages to be COWed, which remain after
	 * truncate_inode_pages finishes, hence the second
	 * unmap_mapping_range call must be made for correctness.
	 */
	unmap_mapping_range(mapping, holebegin, 0, 1);
	truncate_inode_pages(mapping, newsize);
	unmap_mapping_range(mapping, holebegin, 0, 1);
}
EXPORT_SYMBOL(truncate_pagecache);

/**
 * truncate_setsize - update inode and pagecache for a new file size
 * @inode: inode
 * @newsize: new file size
 *
 * truncate_setsize updates i_size and performs pagecache truncation (if
 * necessary) to @newsize. It will be typically be called from the filesystem's
 * setattr function when ATTR_SIZE is passed in.
 *
 * Must be called with a lock serializing truncates and writes (generally
 * i_mutex but e.g. xfs uses a different lock) and before all filesystem
 * specific block truncation has been performed.
 */
void truncate_setsize(struct inode *inode, loff_t newsize)
{
	loff_t oldsize = inode->i_size;

	i_size_write(inode, newsize);
	if (newsize > oldsize)
		pagecache_isize_extended(inode, oldsize, newsize);
	truncate_pagecache(inode, newsize);
}
EXPORT_SYMBOL(truncate_setsize);

/**
 * pagecache_isize_extended - update pagecache after extension of i_size
 * @inode:	inode for which i_size was extended
 * @from:	original inode size
 * @to:		new inode size
 *
 * Handle extension of inode size either caused by extending truncate or by
 * write starting after current i_size. We mark the page straddling current
 * i_size RO so that page_mkwrite() is called on the nearest write access to
 * the page.  This way filesystem can be sure that page_mkwrite() is called on
 * the page before user writes to the page via mmap after the i_size has been
 * changed.
 *
 * The function must be called after i_size is updated so that page fault
 * coming after we unlock the page will already see the new i_size.
 * The function must be called while we still hold i_mutex - this not only
 * makes sure i_size is stable but also that userspace cannot observe new
 * i_size value before we are prepared to store mmap writes at new inode size.
 */
void pagecache_isize_extended(struct inode *inode, loff_t from, loff_t to)
{
	int bsize = i_blocksize(inode);
	loff_t rounded_from;
	struct page *page;
	pgoff_t index;

	WARN_ON(to > inode->i_size);

	if (from >= to || bsize == PAGE_SIZE)
		return;
	/* Page straddling @from will not have any hole block created? */
	rounded_from = round_up(from, bsize);
	if (to <= rounded_from || !(rounded_from & (PAGE_SIZE - 1)))
		return;

	index = from >> PAGE_SHIFT;
	page = find_lock_page(inode->i_mapping, index);
	/* Page not cached? Nothing to do */
	if (!page)
		return;
	/*
	 * See clear_page_dirty_for_io() for details why set_page_dirty()
	 * is needed.
	 */
	if (page_mkclean(page))
		set_page_dirty(page);
	unlock_page(page);
	put_page(page);
}
EXPORT_SYMBOL(pagecache_isize_extended);

/**
 * truncate_pagecache_range - unmap and remove pagecache that is hole-punched
 * @inode: inode
 * @lstart: offset of beginning of hole
 * @lend: offset of last byte of hole
 *
 * This function should typically be called before the filesystem
 * releases resources associated with the freed range (eg. deallocates
 * blocks). This way, pagecache will always stay logically coherent
 * with on-disk format, and the filesystem would not have to deal with
 * situations such as writepage being called for a page that has already
 * had its underlying blocks deallocated.
 */
void truncate_pagecache_range(struct inode *inode, loff_t lstart, loff_t lend)
{
	struct address_space *mapping = inode->i_mapping;
	loff_t unmap_start = round_up(lstart, PAGE_SIZE);
	loff_t unmap_end = round_down(1 + lend, PAGE_SIZE) - 1;
	/*
	 * This rounding is currently just for example: unmap_mapping_range
	 * expands its hole outwards, whereas we want it to contract the hole
	 * inwards.  However, existing callers of truncate_pagecache_range are
	 * doing their own page rounding first.  Note that unmap_mapping_range
	 * allows holelen 0 for all, and we allow lend -1 for end of file.
	 */

	/*
	 * Unlike in truncate_pagecache, unmap_mapping_range is called only
	 * once (before truncating pagecache), and without "even_cows" flag:
	 * hole-punching should not remove private COWed pages from the hole.
	 */
	if ((u64)unmap_end > (u64)unmap_start)
		unmap_mapping_range(mapping, unmap_start,
				    1 + unmap_end - unmap_start, 0);
	truncate_inode_pages_range(mapping, lstart, lend);
}
EXPORT_SYMBOL(truncate_pagecache_range);
