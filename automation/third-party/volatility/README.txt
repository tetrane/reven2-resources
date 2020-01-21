Volatility
==========

Volatility is a very powerful forensic tool that attempts to retrieve high-level information
from a physical memory dump like a crash dump.

Useful links
------------
Quick start documentation: https://github.com/volatilityfoundation/volatility/wiki.
Windows core commands: https://github.com/volatilityfoundation/volatility/wiki/Command-Reference.

Why using Volatility upon Reven2
--------------------------------

With Reven2, we have a very quick access to the physical memory at any moment in the trace.
Consequently, it becomes very easy to use Volatility at any interesting moment in the trace.
We just have to find a point that is worth analyzing deeper and run a Volatility command on it.

In the Uroburos malware article (https://blog.tetrane.com/2019/Analysis-Uroburos-Malware-REVEN.html),
Volatility is used to:
- find an interesting point to start the malware analyze, using the command `callbacks`.
- dump drivers hidden/written by the malware, using the command `moddump`.


Installation
============

Volatility
----------

The basic steps to install Volatility are the following:
```
# Download Volatility from github
git clone https://github.com/volatilityfoundation/volatility.git

# Checkout to a supported release tag
cd volatility
git checkout 2.6.1
```
Some commands may have dependencies, you can find more information about the required dependencies on the Volatility installation page:
https://github.com/volatilityfoundation/volatility/wiki/Installation

Reven2 volatility plugin
------------------------

Copy the Reven2 volatility plugin at the required location inside the volatility directory
```
cp reven2_addrspace.py <volatility dir>/volatility/plugins/addrspaces/
```

How to use
==========

* First of all we must find the profile corresponding to the OS that was used to generate the Reven2 trace.
The list of available Windows profiles can be obtained by looking for the `Profiles` section in the output of the following command:
```
python <volatility dir>/vol.py --info
```
Then we have to select the profile that matches the OS used in the trace.

* Once the profile is selected, we have to find an interesting transition in the trace using Axion or the Reven2 python API.

* Finally, we just have to run the volatility command on the transition using the previously selected profile:
```
python <volatility dir>/vol.py -l <reven2 host>:<reven2 port>:<transition id> --profile <os profile> <volatility command>
```

Example
-------

```
python <volatility dir>/vol.py -l localhost:13370:1000000 --profile Win10x64_10586 pslist
```
