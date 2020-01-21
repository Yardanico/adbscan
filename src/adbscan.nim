import strscans, strformat, threadpool, net
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
  CmdConnect = 0x4e584e43'u32
  CmdConnectMagic = 0xb1a7b1bc'u32
  AdbVersion = 0x01000000
  MaxPayload = 4096


proc newConnectMsg(): Message = 
  ## Creates a new ADB connect message
  result.command = CmdConnect
  result.arg0 = AdbVersion
  result.arg1 = MaxPayload
  result.magic = CmdConnectMagic
  result.data = "host::\x00"
  # Lenght of our data payload
  result.dataLen = uint32(len(result.data))
  # Calculate checksum for our data payload
  for c in result.data:
    result.dataCrc32 += uint32(ord(c))

proc recvMessage(s: Socket, timeout = 3500): Message = 
  ## Receives an ADB Message over a socket
  discard s.recv(addr result, 24)
  if result.magic != CmdConnectMagic or result.dataLen >= 1000:
    raise newException(ValueError, "Invalid data!")
  
  result.data = s.recv(int(result.dataLen), timeout)


proc parsePayload(data: string): string =
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

    var msg = newConnectMsg()
    discard s.send(addr msg, sizeof(msg))

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