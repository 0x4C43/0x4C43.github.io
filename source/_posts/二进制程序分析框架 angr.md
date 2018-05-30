---
title: 二进制程序分析框架 angr
tags:
  - angr
  - binary analysis
categories: Program Analysis
keywords:
  - angr
translate_title: binary-program-analysis-framework-angr
date: 2018-05-29 21:30:00
---

angr 是一个功能强大的二进制程序分析框架，可用于程序的静态分析和动态符号执行。支持 x86、ARM、MIPS 和 PPC 架构中 32 bit 和 64 bit 可执行程序的分析。

# 0x01 安装
angr 是一个 python 库，适用于 python2.x 系列，暂时不支持 python3.x 系列。由于 angr 会对 libz3 和 libVEX 产生修改，为了防止对已安装库的修改而影响其他程序的使用，官方建议在 python 虚拟环境（virtualenvwrapper）中安装和使用 angr。
环境:
>64bit Ubuntu 16.04.4 LTS (Xenial Xerus)    
>Python 2.7.12

## 1. 安装 virtualenvwrapper
virtualenv 是一个可以在同一台计算机中隔离多个 Python 环境的工具。它能够用于创建独立的 Python 环境，使得多个 Python 环境互不影响。virtualenvwrapper 是 virtualenv 的扩展管理包，可以更方便地管理虚拟环境。

使用 pip 命令安装 virtualenvwrapper，默认安装在 /usr/local/bin 目录下。
```bash
pip install virtualenvwrapper
```
配置环境变量 WORKON_HOME 指定虚拟环境管理目录，然后运行 virtualenvwrapper.sh 初始化配置。
```bash
export WORKON_HOME=$HOME/Virtualenv
source /usr/local/bin/virtualenvwrapper.sh
```
为了避免每次使用前手动执行以上命令，可以将其写入 shell 配置文件 ~/.bashrc 或 ~/.zshrc 中。

## 2. 安装依赖包
由于安装 angr 时需要编译一些 C 文件，需要安装 python-dev 和 libffi-dev。
```bash
sudo apt-get install python-dev libffi-dev build-essential
```

## 3. 安装 angr
使用以下命令以开发模式安装 angr，安装完后可修改和重新编译 angr 的各模块，并且这些改动会自动反映到虚拟环境中。
```bash
git clone https://github.com/angr/angr-dev
cd angr-dev
mkvirtualenv angr
./setup.sh -i
```

# 0x02 顶层接口
## 1. Project
angr 模块中的 Project 是分析和模拟二进制可执行文件的基础。分析程序时通过 angr.Project 将二进制程序加载到项目中。
```bash
>>> import angr
>>> proj = angr.Project('fauxware')
```
项目的基本属性有 CPU 架构（arch）、文件路径（filename）、入口地址（entry）。
```bash
>>> import monkeyhex    # 以十六进制显示数字
>>> proj.arch
<Arch AMD64 (LE)>

>>> proj.filename
'fauxware'

>>> proj.entry
0x400580
```

## 2. Loader
angr 的 CLE 模块用于加载二进制程序到虚拟地址空间。加载器（loader）作为项目的一个属性可用于查看与二进制程序一起加载的共享库，并且可在加载地址空间进行查询操作。
```bash
>>> proj.loader
<Loaded fauxware, maps [0x400000:0x5008000]>

>>> proj.loader.min_addr
0x400000
>>> proj.loader.max_addr
0x5008000

>>> proj.loader.shared_objects    # 内存空间中的共享库
{'fauxware': <ELF Object fauxware, maps [0x400000:0x60105f]>,
 u'libc.so.6': <ELF Object libc-2.23.so, maps [0x1000000:0x13c999f]>,
 u'ld-linux-x86-64.so.2': <ELF Object ld-2.23.so, maps [0x2000000:0x2227167]>}

>>> proj.loader.main_object    # 加载到内存空间的主要二进制文件
<ELF Object fauxware, maps [0x400000:0x60105f]>

>>> proj.loader.main_object.execstack    # # 栈是否可执行
False
>>> proj.loader.main_object.pic    # 是否为PIC（位置无关代码）
False
```

## 3. Factory
angr 中有很多类，其中大部分需要在项目中进行实例化。通过 project.factory 可以方便地使用一些常用的对象。
### 1）Blocks
使用 project.factory.block 可从给定的地址提取代码块。
```bash
>>> block = proj.factory.block(proj.entry)
>>> block.pp()
0x400580:       xor     ebp, ebp
0x400582:       mov     r9, rdx
0x400585:       pop     rsi
0x400586:       mov     rdx, rsp
0x400589:       and     rsp, 0xfffffffffffffff0
0x40058d:       push    rax
0x40058e:       push    rsp
0x40058f:       mov     r8, 0x400870
0x400596:       mov     rcx, 0x4007e0
0x40059d:       mov     rdi, 0x40071d
0x4005a4:       call    0x400540
```
此外，还可将 block 转化为 VEX 中间语言形式。
```bash
>>> block.vex.pp()
IRSB {
   t0:Ity_I32 t1:Ity_I32 t2:Ity_I32 t3:Ity_I64 t4:Ity_I64 t5:Ity_I64 t6:Ity_I64
t7:Ity_I64 t8:Ity_I64 t9:Ity_I64 t10:Ity_I64 t11:Ity_I64 t12:Ity_I64 t13:Ity_I64
 t14:Ity_I64 t15:Ity_I32 t16:Ity_I64 t17:Ity_I32 t18:Ity_I64 t19:Ity_I64 t20:Ity
_I64 t21:Ity_I64 t22:Ity_I64 t23:Ity_I64 t24:Ity_I64 t25:Ity_I64 t26:Ity_I64 t27
:Ity_I64 t28:Ity_I64 t29:Ity_I64 t30:Ity_I64 t31:Ity_I64

   00 | ------ IMark(0x400580, 2, 0) ------
   01 | PUT(rbp) = 0x0000000000000000
   02 | ------ IMark(0x400582, 3, 0) ------
   03 | t21 = GET:I64(rdx)
   04 | PUT(r9) = t21
   05 | PUT(pc) = 0x0000000000400585
   06 | ------ IMark(0x400585, 1, 0) ------
   07 | t4 = GET:I64(rsp)
   08 | t3 = LDle:I64(t4)
   09 | t22 = Add64(t4,0x0000000000000008)
   10 | PUT(rsi) = t3
   11 | ------ IMark(0x400586, 3, 0) ------
   12 | PUT(rdx) = t22
   13 | ------ IMark(0x400589, 4, 0) ------
   14 | t5 = And64(t22,0xfffffffffffffff0)
   15 | PUT(cc_op) = 0x0000000000000014
   16 | PUT(cc_dep1) = t5
   17 | PUT(cc_dep2) = 0x0000000000000000
   18 | PUT(pc) = 0x000000000040058d
```

### 2）State
Project 中保存的是程序的初始内存映像，二进制程序执行后的状态由 SimState（simulated program state）表示。SimState 包含程序执行时的状态数据，比如进程内存、寄存器和文件数据等。
```bash
>>> state = proj.factory.entry_state()
>>> state.regs.rip    # 获取寄存器的值
<BV64 0x400580>
>>> state.regs.rax
<BV64 0x1c>

>>> state.mem[proj.entry].int.resolved   # 获取程序入口地址处内存，并解析为int类型
<BV32 0x8949ed31>
```

### 3）Simulation Managers
模拟管理器是 angr 中用于执行和模拟程序的接口，可以管理多个程序状态。stash 为包含多个同类状态的列表，默认执行的 stash 为active。模拟管理器中使用 .step() 以基本 block 为单位运行。
```bash
>>> simgr = proj.factory.simulation_manager(state)
>>> simgr.active
[<SimState @ 0x400580>]

>>> simgr.step()
<SimulationManager with 1 active>

>>> state.regs.rip    # 原始的state未改变
<BV64 0x400580>
>>> simgr.active[0].regs.rip    # 当前state active[0]已改变
<BV64 0x400540>
```
执行之后，active 中的状态已更新，而初始状态 state 未改变。SimState 对象在程序执行时是不变的，所以可以将单个状态用作多次执行的“基础”。

### 4）Analyses
angr 中内置了多种分析功能（analyses）可用于提取程序中的信息，具体有以下 analyses：
```bash
proj.analyses.BackwardSlice          proj.analyses.DFG                   
proj.analyses.BinaryOptimizer         proj.analyses.Disassembly           
proj.analyses.BinDiff                proj.analyses.GirlScout             
proj.analyses.BoyScout              proj.analyses.Identifier            
proj.analyses.CalleeCleanupFinder     proj.analyses.LoopFinder            
proj.analyses.CDG                  proj.analyses.Reassembler          
proj.analyses.CFG                  proj.analyses.reload_analyses       
proj.analyses.CFGAccurate           proj.analyses.StaticHooker          
proj.analyses.CFGFast               proj.analyses.VariableRecovery      
proj.analyses.CongruencyCheck       proj.analyses.VariableRecoveryFast  
proj.analyses.DDG                  proj.analyses.Veritesting         
```
例如使用 proj.analyses.CFGFast 可以生成程序的控制流图。
```bash
>>> proj = angr.Project('fauxware',auto_load_libs=False)   # 不加载共享库

>>> cfg = proj.analyses.CFGFast()
>>> cfg.graph
<networkx.classes.digraph.DiGraph object at 0x7f32d5857110>
>>> len(cfg.graph.nodes())     # 节点数
92
```

# 0x03 分析实例
state.step() 可运行程序，并返回一个 Simsuccessors 对象。符号执行过程中会产生多个后续状态，所以该对象是包含多个状态的列表。

符号执行过程中遇到类似于 if (x > 4) 的分支时，若 x 为符号位向量，angr 会生成一个约束条件 <Bool x_32_1 > 4>。接着执行两个分支，会产生两个后续状态。第一个状态中添加 x > 4 的约束条件，第二个状态中添加 x <  4 的条件。

以程序 [fauxware](https://github.com/angr/angr-doc/tree/master/examples/fauxware) 为例，程序中的 authenticate( ) 函数中存在后门。以“SOSNEAKY”为密码，任何用户名都可以通过验证。
```bash
char *sneaky = "SOSNEAKY";

int authenticate(char *username, char *password)
{
	char stored_pw[9];
	stored_pw[8] = 0;
	int pwfile;

	// evil back d00r
	if (strcmp(password, sneaky) == 0) return 1;

	pwfile = open(username, O_RDONLY);
	read(pwfile, stored_pw, 8);

	if (strcmp(password, stored_pw) == 0) return 1;
	return 0;

}
```

当程序运行到 if (strcmp(password, sneaky) == 0) 分支时会产生两个状态，其中一个状态将会包含用户输入正确后门密码的约束条件。
```bash
>>> proj = angr.Project('fauxware')
>>> state = proj.factory.entry_state()
>>> while True:
...     succ = state.step()
...     if len(succ.successors) == 2:
...         break
...     state = succ.successors[0]

>>> state1,state2 = succ.successors
>>> state1
<SimState @ 0x400692>
>>> state2
<SimState @ 0x400699>
```

模拟执行的目标程序从标准输入中获取数据，默认情况下，angr 会将其视为符号数据流。为了进行符号求解并获得满足条件的输入，需要获取从 stdin 输入数据的引用，可以使用 state.posix.files[0].all_bytes() 获取从 stdin 中读取的数据。
```bash
>>> input_data = state1.posix.files[0].all_bytes()

>>> state1.solver.eval(input_data,cast_to=str)
'\x00\x00\x00\x00\x00\x00\x00\x00\x00SOSNEAKY\x00'

>>> state2.solver.eval(input_data,cast_to=str)
'\x00\x00\x00\x00\x00\x00\x00\x00\x00S\x00\x80N\x00\x00 \x00\x00
```
由求解结果可知，输入后门密码“SOSNEAKY”可进入 state1，即成功通过身份认证。

还可以使用以下脚本求解：
```python
# -*- coding:utf-8 -*-
# !/usr/bin/env python
import angr

proj = angr.Project('fauxware')
simgr = proj.factory.simulation_manager()

simgr.explore(find=lambda s:'Welcome'in s.posix.dumps(1))
state = simgr.found[0]

print state.posix.dumps(0)
```

____
References:   
[1] [angr Documentation](https://www.gitbook.com/book/angr/angr)   