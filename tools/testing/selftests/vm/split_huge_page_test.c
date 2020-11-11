// SPDX-License-Identifier: GPL-2.0
/*
 * A test of splitting PMD THPs and PTE-mapped THPs from a specified virtual
 * address range in a process via <debugfs>/split_huge_pages interface.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <inttypes.h>
#include <string.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <malloc.h>
#include <stdbool.h>
#include <time.h>

uint64_t pagesize;
unsigned int pageshift;
uint64_t pmd_pagesize;

#define PMD_SIZE_PATH "/sys/kernel/mm/transparent_hugepage/hpage_pmd_size"
#define SPLIT_DEBUGFS "/sys/kernel/debug/split_huge_pages"
#define SMAP_PATH "/proc/self/smaps"
#define THP_FS_PATH "/mnt/thp_fs"
#define INPUT_MAX 80

#define PID_FMT "%d,0x%lx,0x%lx,%d"
#define PATH_FMT "%s,0x%lx,0x%lx,%d"

#define PFN_MASK     ((1UL<<55)-1)
#define KPF_THP      (1UL<<22)

int is_backed_by_thp(char *vaddr, int pagemap_file, int kpageflags_file)
{
	uint64_t paddr;
	uint64_t page_flags;

	if (pagemap_file) {
		pread(pagemap_file, &paddr, sizeof(paddr),
			((long)vaddr >> pageshift) * sizeof(paddr));

		if (kpageflags_file) {
			pread(kpageflags_file, &page_flags, sizeof(page_flags),
				(paddr & PFN_MASK) * sizeof(page_flags));

			return !!(page_flags & KPF_THP);
		}
	}
	return 0;
}


static uint64_t read_pmd_pagesize(void)
{
	int fd;
	char buf[20];
	ssize_t num_read;

	fd = open(PMD_SIZE_PATH, O_RDONLY);
	if (fd == -1) {
		perror("Open hpage_pmd_size failed");
		exit(EXIT_FAILURE);
	}
	num_read = read(fd, buf, 19);
	if (num_read < 1) {
		close(fd);
		perror("Read hpage_pmd_size failed");
		exit(EXIT_FAILURE);
	}
	buf[num_read] = '\0';
	close(fd);

	return strtoul(buf, NULL, 10);
}

static int write_file(const char *path, const char *buf, size_t buflen)
{
	int fd;
	ssize_t numwritten;

	fd = open(path, O_WRONLY);
	if (fd == -1)
		return 0;

	numwritten = write(fd, buf, buflen - 1);
	close(fd);
	if (numwritten < 1)
		return 0;

	return (unsigned int) numwritten;
}

static void write_debugfs(const char *fmt, ...)
{
	char input[INPUT_MAX];
	int ret;
	va_list argp;

	va_start(argp, fmt);
	ret = vsnprintf(input, INPUT_MAX, fmt, argp);
	va_end(argp);

	if (ret >= INPUT_MAX) {
		printf("%s: Debugfs input is too long\n", __func__);
		exit(EXIT_FAILURE);
	}

	if (!write_file(SPLIT_DEBUGFS, input, ret + 1)) {
		perror(SPLIT_DEBUGFS);
		exit(EXIT_FAILURE);
	}
}

#define MAX_LINE_LENGTH 500

static bool check_for_pattern(FILE *fp, const char *pattern, char *buf)
{
	while (fgets(buf, MAX_LINE_LENGTH, fp) != NULL) {
		if (!strncmp(buf, pattern, strlen(pattern)))
			return true;
	}
	return false;
}

static uint64_t check_huge(void *addr, const char *prefix)
{
	uint64_t thp = 0;
	int ret;
	FILE *fp;
	char buffer[MAX_LINE_LENGTH];
	char addr_pattern[MAX_LINE_LENGTH];

	ret = snprintf(addr_pattern, MAX_LINE_LENGTH, "%08lx-",
		       (unsigned long) addr);
	if (ret >= MAX_LINE_LENGTH) {
		printf("%s: Pattern is too long\n", __func__);
		exit(EXIT_FAILURE);
	}


	fp = fopen(SMAP_PATH, "r");
	if (!fp) {
		printf("%s: Failed to open file %s\n", __func__, SMAP_PATH);
		exit(EXIT_FAILURE);
	}
	if (!check_for_pattern(fp, addr_pattern, buffer))
		goto err_out;

	/*
	 * Fetch the @prefix in the same block and check the number of
	 * hugepages.
	 */
	if (!check_for_pattern(fp, prefix, buffer))
		goto err_out;

	if (sscanf(&buffer[strlen(prefix)], "%10ld kB", &thp) != 1) {
		printf("Reading smap error\n");
		exit(EXIT_FAILURE);
	}

err_out:
	fclose(fp);
	return thp;
}

void split_pmd_thp(void)
{
	char *one_page;
	size_t len = 4 * pmd_pagesize;
	uint64_t thp_size;
	size_t i;

	one_page = memalign(pmd_pagesize, len);

	if (!one_page) {
		printf("Fail to allocate memory\n");
		exit(EXIT_FAILURE);
	}

	madvise(one_page, len, MADV_HUGEPAGE);

	for (i = 0; i < len; i++)
		one_page[i] = (char)i;

	thp_size = check_huge(one_page, "AnonHugePages:");
	if (!thp_size) {
		printf("No THP is allocated\n");
		exit(EXIT_FAILURE);
	}

	/* split all THPs */
	write_debugfs(PID_FMT, getpid(), (uint64_t)one_page,
		(uint64_t)one_page + len, 0);

	for (i = 0; i < len; i++)
		if (one_page[i] != (char)i) {
			printf("%ld byte corrupted\n", i);
			exit(EXIT_FAILURE);
		}


	thp_size = check_huge(one_page, "AnonHugePages:");
	if (thp_size) {
		printf("Still %ld kB AnonHugePages not split\n", thp_size);
		exit(EXIT_FAILURE);
	}

	printf("Split huge pages successful\n");
	free(one_page);
}

void split_pte_mapped_thp(void)
{
	char *one_page, *pte_mapped, *pte_mapped2;
	size_t len = 4 * pmd_pagesize;
	uint64_t thp_size;
	size_t i;
	const char *pagemap_template = "/proc/%d/pagemap";
	const char *kpageflags_proc = "/proc/kpageflags";
	char pagemap_proc[255];
	int pagemap_fd;
	int kpageflags_fd;

	if (snprintf(pagemap_proc, 255, pagemap_template, getpid()) < 0) {
		perror("get pagemap proc error");
		exit(EXIT_FAILURE);
	}
	pagemap_fd = open(pagemap_proc, O_RDONLY);

	if (pagemap_fd == -1) {
		perror("read pagemap:");
		exit(EXIT_FAILURE);
	}

	kpageflags_fd = open(kpageflags_proc, O_RDONLY);

	if (kpageflags_fd == -1) {
		perror("read kpageflags:");
		exit(EXIT_FAILURE);
	}

	one_page = mmap((void *)(1UL << 30), len, PROT_READ | PROT_WRITE,
			MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);

	madvise(one_page, len, MADV_HUGEPAGE);

	for (i = 0; i < len; i++)
		one_page[i] = (char)i;

	thp_size = check_huge(one_page, "AnonHugePages:");
	if (!thp_size) {
		printf("No THP is allocated\n");
		exit(EXIT_FAILURE);
	}

	/* remap the first pagesize of first THP */
	pte_mapped = mremap(one_page, pagesize, pagesize, MREMAP_MAYMOVE);

	/* remap the Nth pagesize of Nth THP */
	for (i = 1; i < 4; i++) {
		pte_mapped2 = mremap(one_page + pmd_pagesize * i + pagesize * i,
				     pagesize, pagesize,
				     MREMAP_MAYMOVE|MREMAP_FIXED,
				     pte_mapped + pagesize * i);
		if (pte_mapped2 == (char *)-1) {
			perror("mremap failed");
			exit(EXIT_FAILURE);
		}
	}

	/* smap does not show THPs after mremap, use kpageflags instead */
	thp_size = 0;
	for (i = 0; i < pagesize * 4; i++)
		if (i % pagesize == 0 &&
		    is_backed_by_thp(&pte_mapped[i], pagemap_fd, kpageflags_fd))
			thp_size++;

	if (thp_size != 4) {
		printf("Some THPs are missing during mremap\n");
		exit(EXIT_FAILURE);
	}

	/* split all remapped THPs */
	write_debugfs(PID_FMT, getpid(), (uint64_t)pte_mapped,
		      (uint64_t)pte_mapped + pagesize * 4, 0);

	/* smap does not show THPs after mremap, use kpageflags instead */
	thp_size = 0;
	for (i = 0; i < pagesize * 4; i++) {
		if (pte_mapped[i] != (char)i) {
			printf("%ld byte corrupted\n", i);
			exit(EXIT_FAILURE);
		}
		if (i % pagesize == 0 &&
		    is_backed_by_thp(&pte_mapped[i], pagemap_fd, kpageflags_fd))
			thp_size++;
	}

	if (thp_size) {
		printf("Still %ld THPs not split\n", thp_size);
		exit(EXIT_FAILURE);
	}

	printf("Split PTE-mapped huge pages successful\n");
	munmap(one_page, len);
	close(pagemap_fd);
	close(kpageflags_fd);
}

void split_file_backed_thp(void)
{
	int status;
	int fd;
	ssize_t num_written;
	char tmpfs_template[] = "/tmp/thp_split_XXXXXX";
	const char *tmpfs_loc = mkdtemp(tmpfs_template);
	char testfile[INPUT_MAX];
	uint64_t pgoff_start = 0, pgoff_end = 1024;

	printf("Please enable pr_debug in split_huge_pages_in_file() if you need more info.\n");

	status = mount("tmpfs", tmpfs_loc, "tmpfs", 0, "huge=always,size=4m");

	if (status) {
		printf("Unable to create a tmpfs for testing\n");
		exit(EXIT_FAILURE);
	}

	status = snprintf(testfile, INPUT_MAX, "%s/thp_file", tmpfs_loc);
	if (status >= INPUT_MAX) {
		printf("Fail to create file-backed THP split testing file\n");
		goto cleanup;
	}

	fd = open(testfile, O_CREAT|O_WRONLY);
	if (fd == -1) {
		perror("Cannot open testing file\n");
		goto cleanup;
	}

	/* write something to the file, so a file-backed THP can be allocated */
	num_written = write(fd, tmpfs_loc, strlen(tmpfs_loc) + 1);
	close(fd);

	if (num_written < 1) {
		printf("Fail to write data to testing file\n");
		goto cleanup;
	}

	/* split the file-backed THP */
	write_debugfs(PATH_FMT, testfile, pgoff_start, pgoff_end, 0);

	status = unlink(testfile);
	if (status)
		perror("Cannot remove testing file\n");

cleanup:
	status = umount(tmpfs_loc);
	if (status) {
		printf("Unable to umount %s\n", tmpfs_loc);
		exit(EXIT_FAILURE);
	}
	status = rmdir(tmpfs_loc);
	if (status) {
		perror("cannot remove tmp dir");
		exit(EXIT_FAILURE);
	}

	printf("file-backed THP split test done, please check dmesg for more information\n");
}

void create_pagecache_thp_and_fd(const char *testfile, size_t fd_size, int *fd, char **addr)
{
	size_t i;
	int dummy;

	srand(time(NULL));

	*fd = open(testfile, O_CREAT | O_RDWR, 0664);
	if (*fd == -1) {
		perror("Failed to create a file at "THP_FS_PATH);
		exit(EXIT_FAILURE);
	}

	for (i = 0; i < fd_size; i++) {
		unsigned char byte = (unsigned char)i;

		write(*fd, &byte, sizeof(byte));
	}
	close(*fd);
	sync();
	*fd = open("/proc/sys/vm/drop_caches", O_WRONLY);
	if (*fd == -1) {
		perror("open drop_caches");
		exit(EXIT_FAILURE);
	}
	if (write(*fd, "3", 1) != 1) {
		perror("write to drop_caches");
		exit(EXIT_FAILURE);
	}
	close(*fd);

	*fd = open(testfile, O_RDWR);
	if (*fd == -1) {
		perror("Failed to open a file at "THP_FS_PATH);
		exit(EXIT_FAILURE);
	}

	*addr = mmap(NULL, fd_size, PROT_READ|PROT_WRITE, MAP_SHARED, *fd, 0);
	if (*addr == (char *)-1) {
		perror("cannot mmap");
		exit(1);
	}
	madvise(*addr, fd_size, MADV_HUGEPAGE);

	for (size_t i = 0; i < fd_size; i++)
		dummy += *(*addr + i);

	if (!check_huge(*addr, "FilePmdMapped:")) {
		printf("No pagecache THP generated, please mount a filesystem "
			"supporting pagecache THP at "THP_FS_PATH"\n");
		exit(EXIT_FAILURE);
	}
}

void split_thp_in_pagecache_to_order(size_t fd_size, int order)
{
	int fd;
	char *addr;
	size_t i;
	const char testfile[] = THP_FS_PATH "/test";

	create_pagecache_thp_and_fd(testfile, fd_size, &fd, &addr);

	printf("split %ld kB pagecache page to order %d ... ", fd_size >> 10, order);
	write_debugfs(PID_FMT, getpid(), (uint64_t)addr, (uint64_t)addr + fd_size, order);

	for (i = 0; i < fd_size; i++)
		if (*(addr + i) != (char)i) {
			printf("%lu byte corrupted in the file\n", i);
			exit(EXIT_FAILURE);
		}

	close(fd);
	unlink(testfile);
	printf("done\n");
}

void truncate_thp_in_pagecache_to_order(size_t fd_size, int order)
{
	int fd;
	char *addr;
	size_t i;
	const char testfile[] = THP_FS_PATH "/test";

	create_pagecache_thp_and_fd(testfile, fd_size, &fd, &addr);

	printf("truncate %ld kB pagecache page to size %lu kB ... ", fd_size >> 10, 4UL << order);
	ftruncate(fd, pagesize << order);

	for (i = 0; i < (pagesize << order); i++)
		if (*(addr + i) != (char)i) {
			printf("%lu byte corrupted in the file\n", i);
			exit(EXIT_FAILURE);
		}

	close(fd);
	unlink(testfile);
	printf("done\n");
}

void punch_hole_in_pagecache_thp(size_t fd_size, off_t offset[], off_t len[], int n)
{
	int fd, j;
	char *addr;
	size_t i;
	const char testfile[] = THP_FS_PATH "/test";

	create_pagecache_thp_and_fd(testfile, fd_size, &fd, &addr);

	for (j = 0; j < n; j++) {
		printf("addr: %lx, punch a hole at offset %ld with len %ld ... ",
			(unsigned long)addr, offset[j], len[j]);
		fallocate(fd, FALLOC_FL_PUNCH_HOLE|FALLOC_FL_KEEP_SIZE, offset[j], len[j]);
		printf("done\n");
	}

	for (i = 0; i < fd_size; i++) {
		int in_hole = 0;

		for (j = 0; j < n; j++)
			if (i >= offset[j] && i < (offset[j] + len[j])) {
				in_hole = 1;
				break;
			}

		if (in_hole) {
			if (*(addr + i)) {
				printf("%lu byte non-zero after punch\n", i);
				exit(EXIT_FAILURE);
			}
			continue;
		}
		if (*(addr + i) != (char)i) {
			printf("%lu byte corrupted in the file\n", i);
			exit(EXIT_FAILURE);
		}
	}

	close(fd);
	unlink(testfile);
}

int main(int argc, char **argv)
{
	int i;
	size_t fd_size;
	off_t offset[2], len[2];

	if (geteuid() != 0) {
		printf("Please run the benchmark as root\n");
		exit(EXIT_FAILURE);
	}

	setbuf(stdout, NULL);

	pagesize = getpagesize();
	pageshift = ffs(pagesize) - 1;
	pmd_pagesize = read_pmd_pagesize();
	fd_size = 2 * pmd_pagesize;

	split_pmd_thp();
	split_pte_mapped_thp();
	split_file_backed_thp();

	for (i = 8; i >= 0; i--)
		if (i != 1)
			split_thp_in_pagecache_to_order(fd_size, i);

	/*
	 * for i is 1, truncate code in the kernel should create order-0 pages
	 * instead of order-1 THPs, since order-1 THP is not supported. No error
	 * is expected.
	 */
	for (i = 8; i >= 0; i--)
		truncate_thp_in_pagecache_to_order(fd_size, i);

	offset[0] = 123;
	offset[1] = 4 * pagesize;
	len[0] = 200 * pagesize;
	len[1] = 16 * pagesize;
	punch_hole_in_pagecache_thp(fd_size, offset, len, 2);

	offset[0] = 259 * pagesize + pagesize / 2;
	offset[1] = 33 * pagesize;
	len[0] = 129 * pagesize;
	len[1] = 16 * pagesize;
	punch_hole_in_pagecache_thp(fd_size, offset, len, 2);

	return 0;
}
