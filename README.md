Pegasus project
==============
* ![Version](https://img.shields.io/badge/Version-0.1.pegasus-brightgreen.svg) *windbg emulation plugin*
* ![Version](https://img.shields.io/badge/Version-0.2.dbgsuit-red.svg) *anti anti reversing plugin for windbg*

Engine
-------
* unicorn : https://github.com/unicorn-engine/unicorn
* distorm : https://github.com/gdabah/distorm

Build
-------
![MSVC](https://img.shields.io/badge/msvc-x86-brightgreen.svg)
![MSVC](https://img.shields.io/badge/msvc-x64-brightgreen.svg)

Support
-------
![Support](https://img.shields.io/badge/Support-LiveDebugging-brightgreen.svg)
![Support](https://img.shields.io/badge/Support-FullDump-brightgreen.svg)
![Support](https://img.shields.io/badge/Working-CompleteMemoryDump-yellow.svg)

Video
-------
* ![Version](https://img.shields.io/badge/Version-prototype.pegasus-brightgreen.svg) https://goo.gl/TBNaHf
* ![Version](https://img.shields.io/badge/Version-0.1.pegasus-brightgreen.svg)

Screenshot
-------
![](./screenshot/0.PNG)
![](./screenshot/1.PNG)
![](./screenshot/2.PNG)
![](./screenshot/3.PNG)
![](./screenshot/4.PNG)
![](./screenshot/5.PNG)

Commands
-------
<pre>
0:000> .load pegasus.dll
*****************************************************
*                                                   *
*         PEGASUS - Windbg emulation plugin         *
*                                                   *
*****************************************************

0:000> !attach -?
; 0:000> !attach command attached the current target application to the emulator.

0:000> !detach -?
; 0:000> !detach command detached the current target application to the emulator.

0:000> !trace -?
; !trace [/so] [/bp <bp>]
;  /bp - break point. (space-delimited)
;  /so - step over.
; 0:000> !trace command executes a single instruction.

0:000> !steps -?
; 0:000> !steps command displays the trace step.

0:000> !dbvm -?
; !dbvm [/a <a>] [/l <l>]
;  /a <a> - address (space-delimited)
;  /l <l> - length (space-delimited)
; 0:000> !dbvm commands display the contents of memory in the given range.

0:000> !regs -?
; 0:000> !reg command displays current registers.
</pre>
