pegasus
-------
* Windbg extension DLL for emulation
* ![Build](https://img.shields.io/badge/build-passing-brightgreen.svg)
* ![Support](https://img.shields.io/badge/support-live-brightgreen.svg) ![Support](https://img.shields.io/badge/support-dump-brightgreen.svg)

demo
-------
* video - https://goo.gl/TBNaHf
* [screenshots](https://github.com/0a777h/pegasus/tree/master/screenshot)

commands
-------
<pre>
0:000> .load pegasus.dll
*****************************************************
*                                                   *
*         PEGASUS - Windbg emulation plugin         *
*                                                   *
*****************************************************

0:000> !attach -?
; 0:000> !attach command attachs the current target application to the emulator.

0:000> !detach -?
; 0:000> !detach command detachs the current target application to the emulator.

0:000> !trace -?
; !trace [/so] [/bp <bp>]
;  /bp - break point. (space-delimited)
;  /so - step over.
; 0:000> !trace command executes a single instruction.

0:000> !steps -?
; 0:000> !steps command displays the trace step.

0:000> !ddvm -?
0:000> !dbvm -?
; !dbvm [/a <a>] [/l <l>]
;  /a <a> - address (space-delimited)
;  /l <l> - length (space-delimited)
; 0:000> !dbvm command displays the contents of memory in the given range.

0:000> !regs -?
; 0:000> !reg command displays current registers.
</pre>

inside
-------
* [unicorn-engine](http://www.unicorn-engine.org/)
* [distorm](https://github.com/gdabah/distorm)

special thanks
-------
[chae](http://trunk.so/) - malware researcher and analyst
