# ARMv7 Fault Injection
Simulating ARMv7-A fault injection attacks using Unicorn Engine.

### About
This project is inspired by [FiSim](https://github.com/Riscure/FiSim) and is compatible* with the same 32bit binary's.  
The main goal of this project is to provide a minimal implementation to enables playing around with the setup without recompilation (FiSim is written in .net).

The fault injection models used are slightly different than those used by default in FiSim, as instructions are permanently changed during execution instead only the first time that instruction is executed.

I have experimented with multiprocessing and  Unicorn Engine 2, which made simulations significantly faster than FiSim, but it is omitted here to keep the code simple. 

_*otpperifirals are not implemented_
