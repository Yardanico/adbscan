import strutils

switch("opt", "speed")
when defined(zigcc):
  switch("cc", "clang")
  switch("clang.exe", "zigcc")
  switch("clang.linkerexe", "zigcc")
  switch("passL", "-fno-sanitize=undefined")
  switch("passC", "-fno-sanitize=undefined")
  case hostCPU
  of "amd64": 
    switch("passC", "-target x86_64-linux-musl")
    switch("passL", "-target x86_64-linux-musl")
  of "i386": 
    switch("passC", "-target i386-linux-musl")
    switch("passL", "-target i386-linux-musl")

# Cross-compile to a Windows .exe
when defined(crosswin):
  switch("cc", "gcc")
  let mingwExe = 
    if hostCPU == "amd64":
      "x86_64-w64-mingw32-gcc"
    elif hostCPU == "i386":
      "i686-w64-mingw32-gcc"
    else: 
      "error"
  switch("gcc.linkerexe", mingwExe)
  switch("gcc.exe", mingwExe)
  switch("gcc.path", findExe(mingwExe).rsplit("/", 1)[0])
  switch("gcc.options.linker", "")
  switch("os", "windows")
  switch("define", "windows")