adbscan
======

A simple utility for scanning IP addresses for unprotected ADB Android devices.
Written in the Nim programming language, portable (works on most OSes and architectures out there)

Binary releases are available in GitHub Releases tab, for building from source install Nim (with nimble), clone the repository, then go to the repository directory, and run

```nimble build```


## Current status
Currently the utility can send a simple ADB connection message to the device, receive
an answer, and parse it

## Output file format
Example file output:
```
ip: 1.2.3.4 name: Hi3798MV100, model: Hi3798MV100, device: Hi3798MV100
ip: 1.2.3.4 name: marlin, model: Pixel XL, device: marlin
ip: 1.2.3.4 name: rk322x_box, model: rk322x-box, device: rk322x_box
ip: 1.2.3.4 name: aosp_noa_8g, model: TV6586_DVB, device: noa_8g
ip: 1.2.3.4 name: NV501WAC, model: NV501WAC, device: NV501WAC
ip: 1.2.3.4 name: p281, model: Hybrid 2, device: p281
ip: 1.2.3.4 name: rk322x, model: UHD-G101_V2, device: rk322x
```

For devices which aren't able to be parsed by adbscan the entry will look like
```
ip: 1.2.3.4 device info: device::http://ro.product.name =starltexx;ro.product.model=SM-G960F;ro.product.device=starlte;features=cmd,stat_v2,shell_v2
```

This program also has a simple progress bar in the terminal. 
It's not 100% representative of real "found" count since with rescans
two IPs can be scanned asynchronously.  
```
165 / 313, found 1
```

## Command line options
```
$ adbscan --help

Usage:
  cmdline [optional-params] 
Options:
  -h, --help                                 print this cligen-erated help
  --help-syntax                              advanced: prepend,plurals,..
  -i=, --input=        string     "ips.txt"  Input file
  -o=, --output=       string     "out.txt"  Output file
  -p=, --parseMode=    ParseMode  PlainText  Input file format: PlainText (default), Masscan
  -w=, --workers=      int        512        Amount of workers to use
  -r=, --rescanCount=  int        2          Amount of requests to be sent to a single IP (1 for a single scan)
```

- `PlainText` mode (which is the default) accepts input file as a line-delimited list of IPs. For example:

```
1.2.3.4
3.4.5.6
5.6.6.7
```

- `Masscan` mode accepts output of a Masscan's `-oL` output file. For example:
```
#masscan
open tcp 5555 1.2.3.4 1611375649
open tcp 5555 4.5.6.7 1611375649
# end
```