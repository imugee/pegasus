Pegasus - Windbg emulation plugin
==============
[![Page](https://img.shields.io/badge/Page-http://0a777h.blogspot.kr/2017/07/11_20.html-brightgreen.svg)](http://0a777h.blogspot.kr/2017/07/11_20.html)
[![Video](https://img.shields.io/badge/Video-goo.gl/TBNaHf-lightgrey.svg)](https://goo.gl/TBNaHf)
[![email](https://img.shields.io/badge/email-0a777h@gmail.com-blue.svg)](0a777h@gmail.com)

Version
-------
Prototype-version

Commands
-------
<pre>
0:000> !attach
eax=00a68320 ebx=009d0000 ecx=00000000 edx=00000000 esi=76536314 edi=76536308
eip=00f41040 esp=007bf8f4 ebp=007bf938
...
00000000`00f41040 680821f400      push    offset test!`string' (00000000`00f42108)

0:000> !mov eax 0
mov   eax,0

0:000> !regs
eax=00000000 ebx=009d0000 ecx=00000000 edx=00000000 esi=76536314 edi=76536308
eip=00f41040 esp=007bf8f4 ebp=007bf938
...

0:000> !swch
64bit or 32bit
...

0:000> !trace
eax=00a68320 ebx=009d0000 ecx=00000000 edx=00000000 esi=76536314 edi=76536308
eip=00f41045 esp=007bf8f0 ebp=007bf938
...
00000000`00f41045 ff151020f400    call    qword ptr [00000000`01e8305b]

0:000> !trace -r 00f4104b 
eax=00a68320 ebx=009d0000 ecx=00000000 edx=00000000 esi=76536314 edi=76536308
eip=7638cf60 esp=007bf8ec ebp=007bf938
...
00000000`7638cf60 8bff            mov     edi,edi
...
eax=77d70000 ebx=009d0000 ecx=2392c6cb edx=00000000 esi=76536314 edi=76536308
eip=00f4104b esp=007bf8f4 ebp=007bf938
...
00000000`00f4104b 681c21f400      push    offset test!`string' (00000000`00f4211c)

...
</pre>
