---
title: American Fuzzy Lop
tags:
  - Fuzz
categories: Fuzz
keywords:
  - AFL
  - Fuzz
translate_title: american-fuzzy-lop
date: 2018-07-22 21:50:34
---

AFL 是一种安全导向的模糊测试工具，它采用一种新型的编译时插桩和遗传算法来自动生成测试样本，使用这些样本可触发目标二进制程序中新的内部状态，从而可提高模糊测试的代码覆盖率。与其他插桩模糊测试工具相比，afl-fuzz 的设计更具有实用性：具有适度的性能开销，使用各种高效的模糊策略，配置简单，并能够处理复杂的实际使用案例（比如常见的图像解析或文件压缩库）。

# 0x01 American Fuzzy Lop

## 1. 导向性 Fuzz
fuzzer 生成测试样例的盲目性和随机性导致模糊测试只能找到浅层代码中的漏洞，由于无法抵达被测程序的某些代码路径，使得一些漏洞无法使用 fuzzer 找到。

目前已有大量的方法试图解决对于该问题。最早的方案是由 Tavis Ormandy 提出的语料库提蒸馏法（corpus distillation），该方案根据覆盖率信息从大量的种子中选取感兴趣的种子得到一个高质量的语料库，然后通过传统的方法利用这些高质量的语料库对目标程序进行模糊测试。该方案有较好的效果，但需要有较好的语料库。此外， 代码覆盖率也只是衡量程序执行状态的一个简单化的度量，对于长期模糊测试的引导作用较小。

另外，更复杂的研究主要包括动态符号执行（concolic execution）、符号执行和静态分析。这些技术在实验环境下具有很好的前景，但在实际应用中存在可靠性和性能问题。因此，目前还没有一个较好的方案能替代 "dumb" fuzzing 技术。

## 2. afl-fuzz 算法
AFL 是一款基于插桩引导和遗传算法的模糊测试器，并使用边缘覆盖（edge coverage）来获取程序控制流（CFG）的变化。AFL 算法如下：
- 1）加载初始测试用例到队列；
- 2）从队列中获取下一个输入文件；
- 3）在不改变程序行为的前提下，尝试修剪测试用例，最小化其 size；
- 4）使用传统的模糊策略重复变异文件；
- 5）若通过插桩检测到变异后的文件能触发新的状态转换，则将该变异文件加入队列；
- 6）回到 2 执行。

对于找到的测试样例，也会周期性地用更新的、高覆盖率的测试样例进行替换。

## 3. 插桩目标程序
有源码的情况下，可使用 gcc 或 clang 编译时进行插桩。
```bash
$ CC=/path/to/afl/afl-gcc ./configure  # for C program
$ CXX=/path/to/afl/afl-g++ ./configure   # for C++ program
$ make clean all
```
为了方便测试 lib 库中程序，可使用静态编译的方法将库编译到可执行文件中。
```bash
CC=/path/to/afl/afl-gcc ./configure --disable-shared
make
```
此外，编译时设置 `AFL_HARDEN=1` 选项可用于检测简单的内存溢出漏洞，方便对 crash 样本的分析，具体可看  notes_for_asan.txt。

只有二进制程序的情况下，可以使用 QEMU 进行插桩。该功能开启方法如下：
```bash
$ sudo apt install libtool-bin
$ cd qemu_mode
$ ./build_qemu_support.sh
```

## 4. 选择初始测试用例
测试样例的选择应遵循以下原则：
- 文件尽量小。小于 1 kb 的文件是理想的。
- 只有在每个测试用例都能驱动程序中的不同功能的情况下，才有必要使用多个测试用例。

注：如果测似样例语料库较大，可以使用 afl-cmin 识别能触发程序走不同功能代码的文件，得到有效的样本集。

## 5. Fuzzing 目标程序
对于从 stdin 中获取输入的目标程序，使用以下方法进行测试：
```bash
$ ./afl-fuzz -i testcase_dir -o findings_dir /path/to/program [...params...]
```
对于从文件中获取输入的目标程序，使用 '@@' 作为输入文件的占位符，afl-fuzz 会自动使用测试样本目录下的文件进行替换。
```bash
$ ./afl-fuzz -i testcase_dir -o findings_dir /path/to/program @@
```
参数说明：
- -i：指定输入样例所在的目录；
- -o：指定输出结果的存放目录；
- -Q ：指定对未插桩程序进行 QEMU Fuzz 模式；
- -n：指定对未插桩程序进行传统的 blind Fuzz 模式；
- -m：设置程序执行的内存限制；
- -t：设置程序执行的超时；
- -d：quick & dirty 模式。

Fuzz 性能优化可参看 perf_tips.txt。

## 6. 结果输出
在输出结果目录中有 3 个子目录：
- queue：能覆盖不同执行路径的所有测试样例。在使用这些测试样例前，可使用 afl-cmin 筛选出更有代表性的样例。
- crashes：存放能触发被测试程序 crash 的样例。
- hangs：存放可导致被测试程序超时的样例。

使用 afl-min 最小化测试样例集：
```bash
$ ./afl-tmin -i test_case -o minimized_result -- /path/to/program [...]
```

使用以下命令可继续已停止的测试任务：
```bash
$ ./afl-fuzz -i- -o existing_output_dir [...etc...]
```
注：
- 通过 afl-plot 可生成[测试图](http://lcamtuf.coredump.cx/afl/plot/)。
- 使用 [afl-cov](https://github.com/mrash/afl-cov) 可获得测试用例的代码覆盖率。


## 7. 并行测试
每个 afl-fuzz 实例只占用一个 cpu 核，在多核系统中使用并行化测试可提高对硬件的利用率（使用 afl-gotcpu 可查看 CPU 的使用状态）。此外，并行 Fuzzing 模式还提供简单的接口给其他的测试工具，包括符号执行引擎。

在搭载多核 CPU 的系统中可同时运行多个测试实例。首先使用 -M 参数启动一个主实例（Master）。
```bash
$ ./afl-fuzz -i testcase_dir -o sync_dir -M fuzzer01 [...other stuff...]
```
接着，使用 -S 运行多个从属实例（Slave）：
```bash
$ ./afl-fuzz -i testcase_dir -o sync_dir -S fuzzer02 [...other stuff...]
$ ./afl-fuzz -i testcase_dir -o sync_dir -S fuzzer03 [...other stuff...]
```
所有测试实例共享同一个输出文件夹 sync_dir，同时每个测试实例使用单独的文件（ path/to/sync_dir/fuzzer01/）夹存放其运行状态。每个测试实例会周期性地扫描 sync_dir 目录下由其它测试实例生成的用例，并将有用的样例加入到自己的样例集中。

使用 afl-whatsup 可监控 afl-fuzz 的运行状态，当测试实例无法找到新的路径时将会被终止运行。其它内容可参考 paralled_fuzzing.txt。

## 8. 测试字典
默认情况下，afl-fuzz 变异引擎适用于紧凑数据格式 - 例如，图像，多媒体，压缩数据，正则表达式语法或 shell 脚本。它不太适合特别繁琐和冗长的语言 - 包括HTML，SQL或 JavaScript。

afl-fuzz 支持在测试过程中使用字典，字典中为语言的关键字、magic headers 或其他一些与目标数据类型相关的符号。使用 -x 选项可使用该功能。

## 9. Crash 分类
在得到崩溃样例之后，需要评估其可利用性。使用 -C 选项可开启 afl-fuzz 的 `crash exploration` 模式，该模式下，fuzzer 使用崩溃样例作为输入，输出的样例集为可以快速检查攻击者可控制错误地址被控制的程度。

此外，还可以使用 GDB 插件 [exploitable](https://github.com/jfoote/exploitable) 判断 crash 是否可利用。

[Address Sanitizer(ASAN)](https://github.com/google/sanitizers) 是强大的内存检测工具，它可检测出缓存区溢出、UAF 等内存漏洞，编译时可使用以下选项开启 Address Sanitizer。
```bash
AFL_USE_ASAN=1 ./configure CC=afl-gcc CXX=afl-g++ LD=afl-gcc--disable-shared
AFL_USE_ASAN=1 make
```
afl-fuzz 测试编译时开启 Address Sanitizer 的程序会大大减慢测试速度，但可以发现更多 bug。

不使用 AFL 编译插桩时，可使用以下方式开启 Address Sanitizer。
```bash
./configure CC=gcc CXX=g++ CFLAGS="-g -fsanitize=address"
make
```

# 0x02 性能优化
当模糊测试速度太慢时，可通过以下方式优化测试性能，提高测试速度。  
**1.  测试样例尽量小**

**2. 使用 LLVM 插桩**  
使用 LLVM 插桩可得到 2 倍的性能提升。 LLVM 插桩的程序可支持 `persistent` 和 `deferred fork server` 模式，使用这两种模式也能使性能提升。

**3. 使用并行化测试**  
每个 fuzzer 只需要一个内核，因此，在一个 4 核的计算机上可以同时开启 4 个 fuzzer。

**3. 控制内存使用和超时**  
使用 -t 选项可设定程序运行的超时值；有些程序会花费大量时间用于分配和初始化内存，使用 -m 选项可限定内存使用大小。


____
References:   
[1] [american fuzzy lop](http://lcamtuf.coredump.cx/afl/README.txt)   
[2] [afl-training](https://github.com/ThalesIgnite/afl-training)  
