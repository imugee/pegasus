dbgsuit - windbg extension DLL for anti anti debugging
-------
![Build](https://img.shields.io/badge/build-passing-brightgreen.svg)
![Support](https://img.shields.io/badge/support-live-brightgreen.svg) 

demo - dbgsuit & pegasus
-------
* video - https://goo.gl/rf62DZ

commands
-------
* test.bat - please copy it to windbg path
<pre>
start /b windbg.exe -pv -pn test.exe
</pre>

* suspend.dll - please copy it to windbg path
* dbgsuit.dll
<pre>
0:000> .load dbgsuit.dll
0:000> suspend -p [rip | eip]
</pre>
