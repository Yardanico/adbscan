import strutils
switch("threads", "on")
warning("UnusedImport", off)


# Cross-compile for Windows (works at least on Arch and macOS with mingw-w64)
when defined(crosswin):
  switch("cc", "gcc")
  let mingwExe = "x86_64-w64-mingw32-gcc"
  switch("gcc.linkerexe", mingwExe)
  switch("gcc.exe", mingwExe)
  switch("gcc.path", findExe(mingwExe).rsplit("/", 1)[0])
  switch("gcc.options.linker", "")
  switch("os", "windows")
  switch("define", "windows")