Rabbit
======

Rabbit is a native debugger written in ruby that is meant to be fully scriptable.

Features
========
* Breakpoints (software and hardware)
* Customizable debug event handling
* Attach or load processes
* Disassembly

Planned Features
================
* Single stepping
* X86_64 support
* Symbol processing via dbghlp.dll

Example Usage
=============
```ruby
rabbit = Rabbit::Debugger.new
rabbit.load("calc.exe")
rabbit.enable_bp(0x01007b0e) # break on loading the help dialog
rabbit.list_bps # list all breakpoints
rabbit.run # let calc.exe run
```