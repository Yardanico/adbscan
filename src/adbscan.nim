import strscans, strformat, threadpool, net, streams
import cligen
import sugar

type
  ## Message object as described per ADB protocol
  Message = object
    command: uint32
    arg0, arg1: uint32
    dataLen: uint32
    dataCrc32: uint32
    magic: uint32
    data: string
  
  ## Parse mode for input files 
  ParseMode = enum
    Masscan, PlainText


const
  CmdSync = 0x434e5953'u32
  CmdClose = 0x45534c43'u32
  CmdWrite = 0x45545257'u32
  CmdOpen = 0x4e45504f'u32
  CmdConnect = 0x4e584e43'u32
  CmdOkay = 0x59414b4f'u32
  # Calculate all possible magic values for all commands to check correctness
  PossibleMagic = collect(newSeq):
    for cmd in [CmdSync, CmdClose, CmdWrite, CmdOpen, CmdConnect, CmdOkay]:
      cmd xor 0xffffffff'u32
  AdbVersion = 0x01000000
  MaxPayload = 4096


proc newMessage(cmd: uint32, arg0, arg1: uint32, data: string): Message = 
  ## Creates a new Message object
  result.command = cmd
  result.arg0 = arg0
  result.arg1 = arg1
  result.magic = result.command xor 0xffffffff'u32
  # Lenght of our data payload
  result.dataLen = uint32(len(data))
  # Calculate checksum for our data payload
  for c in data:
    result.dataCrc32 += uint32(ord(c))
  result.data = data


proc send(s: Socket, m: Message) = 
  ## Sends an ADB Message over a socket
  var strm = newStringStream()
  defer: strm.close()

  strm.write(m.command)
  strm.write(m.arg0)
  strm.write(m.arg1)
  strm.write(m.dataLen)
  strm.write(m.dataCrc32)
  strm.write(m.magic)
  strm.write(m.data)
  strm.setPosition(0)

  let encoded = strm.readAll()
  s.send(encoded)


proc recvMessage(s: Socket, timeout = 3500): Message = 
  ## Receives an ADB Message over a socket
  ##
  ## You can optionally specify `timeout` for waiting in ms
  let msgInfo = newStringStream(s.recv(24, timeout))
  defer: msgInfo.close()
  result.command = msgInfo.readUint32()
  result.arg0 = msgInfo.readUint32()
  result.arg1 = msgInfo.readUint32()
  result.dataLen = msgInfo.readUint32()
  result.dataCrc32 = msgInfo.readUint32()
  result.magic = msgInfo.readUint32()
  # Check if the response is malformed
  if result.magic notin PossibleMagic or result.dataLen >= 1000:
    raise newException(ValueError, "Invalid client!")
  
  # -1 since we don't really need the null character in the end
  result.data = s.recv(int(result.dataLen - 1), timeout)


proc parsePayload(data: string): string =
  result = ""
  var name, model, device: string
  const scanStr = "device::ro.product.name=$+;ro.product.model=$+;ro.product.device=$+;"
  if scanf(data, scanStr, name, model, device):
    result = &"name: {name}, model: {model}, device: {device}" 


proc tryGetInfo(ip: string): string = 
  ## Checks if the Android Debug Bridge is hosted on a specified IP
  ##
  ## Returns "" if there is no ADB running, otherwise returns device info
  var s = newSocket()
  defer: s.close()
  try:
    s.connect(ip, Port(5555), timeout = 5000)

    let msg = newMessage(CmdConnect, AdbVersion, MaxPayload, "host::\x00")
    s.send(msg)

    let reply = s.recvMessage(3500)
    # If device is "unauthorized" then we will not get this
    if "device" in reply.data:
      return parsePayload(reply.data) 
  except:
    # echo getCurrentExceptionMsg()
    return ""


proc parseFile(file: File, mode: ParseMode): seq[string] =
  ## Parses the file in specified `mode` (ParseMode)
  ##
  ## Returns a sequence of IPs
  result = @[]
  while not file.endOfFile():
    let line = file.readLine()
    if line == "": continue
    case mode
    of Masscan:
      var ip: string
      if scanf(line, "open tcp 5555 $+ ", ip):
        result.add(ip)
    of PlainText:
      result.add(line)


proc cmdline(input = "ips.txt", output = "out.txt", parseMode = PlainText, threads = 256) = 
  var inputFile: File
  try: 
    inputFile = open(input, fmRead)
  except:
    quit(&"Cannot open {input} for reading!", 1)
  
  var outFile: File
  try:
    outFile = open(output, fmWrite)
  except:
    quit(&"Cannot open {output} for writing!", 1)
  
  let ips = parseFile(inputFile, parseMode)
  inputFile.close()

  var results = newSeq[FlowVar[string]](len(ips))
  setMaxPoolSize(threads)
  for i, ip in ips:
    results[i] = spawn tryGetInfo(ip)
  
  # Wait for all threads to complete
  sync()

  for i, resData in results:
    let res = ^resData
    if res == "": continue
    outFile.writeLine(&"ip: {ips[i]} {res}")
  
  outFile.flushFile()
  outFile.close()


when isMainModule:
  # Use cligen to generate all command-line arguments with custom help
  dispatch(
    cmdline, 
    help = {
      "input": "Input file",
      "output": "Output file",
      "parseMode": "Input file format: Masscan, PlainText",
      "threads": "Amount of threads (256 is the maximum)"
    }
  )