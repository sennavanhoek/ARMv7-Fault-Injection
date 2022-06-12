# ARMv7 Fault Injection
Simulating ARMv7-A fault injection attacks using Unicorn Engine.

### About
This project is inspired by [FiSim](https://github.com/Riscure/FiSim) and is compatible* with the same 32 bit binaries.  
The main goal of this project is to provide a minimal implementation to enable playing around with the setup without recompilation (FiSim is written using .net).

The fault injection models used are slightly different than those used by default in FiSim, as instructions are permanently changed (cashed) during execution instead only the first time that instruction is executed (transient). This both kept the models simple and it's interesting to compare the slightly different glitches found, although most will be exactly the same.

I have experimented with multiprocessing and  Unicorn Engine 2, which made simulations significantly faster than FiSim, but it is omitted here to keep the code simple.

_*otpperifirals are not implemented_



