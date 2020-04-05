---
title: IDAPyhon 脚本批量分析程序
date: 2018-08-03 09:20:18
tags: [IDAPython]
categories: Program Analysis
keywords: [IDAPython]
---

当我们需要对大量二进制文件进行分析时，使用 Python 将其自动化，可以极大的提高效率。

# 0x01 运行 IDA
IDA 可以使用命令行的方式启动，并且支持图形化接口和终端文本形式的接口。
```bash
ida input-file        (Start graphical interface)
idat input-file       (Start text interface)
```
同时可使用以下参数：
> -A        autonomous mode. IDA will not display dialog boxes. Designed to be used together with -S switch.  
> -c         disassemble a new file (delete the old database)  
> -L###  name of the log file  
> -S###  Execute a script file when the database is opened.  

使用以下命令可运行 IDA，自动加载二进制文件 input-file 进行分析，并运行 IDAPython 脚本 `analysis.py`。
```bash
ida -c -Lida.log -A -Sanalysis.py input-file
```
需注意，日志文件名 `ida.log` 与 `-L` 之间，以及脚本文件名 `analysis.py` 与 `-S` 间都没有空格。

# 0x02 批量处理
首先，需要修改分析二进制程序的 IDAPython 脚本 `analysis.py`，使得该脚本文件在 IDA 分析完二进制程序后才被执行，同时在执行完后，关闭 IDA。
```python
import idaapi
import idautils
import idc

def do_some_analyse():
    pass

def main():
    idc.Wait()   # 待 IDA 分析完程序后执行
    do_some_analyse()
    idc.Exit(0)  # 关闭 IDA

if __name__ == "__main__":
    main()
```
接着，通过以下脚本自动加载并调用 `analysis.py` 脚本分析 `pefile` 文件夹中的 PE 文件。
```python
!#/usr/bin/env/ python
import os
import subprocess

ida_path = "D:/Program Files/IDA 7.0/ida.exe"
work_dir = os.path.abspath('.')
pefile_dir = os.path.join(work_dir, 'pefile')
script_path = os.path.join(work_dir, "analysis.py")

for file in os.listdir(pefile_dir):
    # cmd_str = ida.exe -Lida.log -c -A -Sanalysis.py pefile
    cmd_str = '{} -Lida.log -c -A -S{} {}'.format(ida_path, script_path, os.path.join(pefile_dir, file))
    print(cmd_str)
    if file.endswith('dll') or file.endswith('exe'):
        p = subprocess.Popen((cmd_str))
        p.wait()
```
____
References:   
[1] [Command line switches](https://www.hex-rays.com/products/ida/support/idadoc/417.shtml)   
[2] [Using IDAPython to Make Your Life Easier: Part 6](https://researchcenter.paloaltonetworks.com/2016/06/unit42-using-idapython-to-make-your-life-easier-part-6/)   

