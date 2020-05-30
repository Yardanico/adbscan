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

This program also outputs a simple progress bar in the terminal which looks like that:
```
165 / 313, found 1
```

## Command line options
```
adbscan --help

Usage:
  cmdline [optional-params] 
Options:
  -h, --help                                 print this cligen-erated help
  --help-syntax                              advanced: prepend,plurals,..
  -i=, --input=        string     "ips.txt"  Input file
  -o=, --output=       string     "out.txt"  Output file
  -p=, --parseMode=    ParseMode  Masscan    Input file format: Masscan, PlainText
  -w=, --workers=      int        512        Amount of workers to use
  -r=, --rescanCount=  int        3          Amount of requests to be sent to a single IP
```