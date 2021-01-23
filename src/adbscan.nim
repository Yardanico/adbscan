import std / [
  asyncdispatch, asyncnet,
  strutils, strscans, strformat,
  options,
  tables, sequtils,
  terminal,
  random
]

import pkg / cligen

randomize()

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

  OutputType = enum
    Auto, Text, Json, Csv
  
  ScanResult = object
    name: string
    model: string
    device: string
    rawData: string

const
  CmdConnect = 0x4e584e43'u32
  CmdConnectMagic = 0xb1a7b1bc'u32
  AdbVersion = 0x01000000
  MaxPayload = 4096

proc newConnectMsg(): Message = 
  ## Creates a new ADB connect message
  result = Message(
    command: CmdConnect,
    arg0: AdbVersion,
    arg1: MaxPayload,
    magic: CmdConnectMagic,
    data: "host::\x00",
    # Lenght of our data payload
    dataLen: uint32(len(result.data)),
    # Calculate checksum for our data payload
    dataCrc32: block:
      var crc = 0'u32
      for c in result.data:
        crc += uint32(ord(c))
      crc
  )

proc recvMessage(s: AsyncSocket): Future[Option[Message]] {.async.} = 
  ## Receives an ADB Message over a socket
  var msg: Message

  if (await s.recvInto(addr msg, 24)) != 24:
    # Expected 24 bytes
    return
  
  if msg.magic != CmdConnectMagic or msg.dataLen >= 1000:
    # Invalid data
    return
  
  if msg.dataLen > 0:
    msg.data = await s.recv(int(msg.dataLen))
  
  # Verify the data checksum
  var crc = 0'u32
  for c in msg.data:
    crc += uint32(ord(c))
  
  if crc != msg.dataCrc32:
    # crc32 checksum doesn't match
    return

  result = some(msg)

proc parsePayload(ip, data: string): ScanResult =
  result = ScanResult(rawData: data)
  var tmp, name, model, device: string
  const scanStr = "device::$*ro.product.name$*=$+;ro.product.model=$+;ro.product.device=$+;"

  if scanf(data, scanStr, tmp, tmp, name, model, device):
    result.name = name
    result.model = model
    result.device = device

var 
  maxWorkers = 0                      # Maximum number of allowed workers
  curWorkers = 0                      # Current amount of workers
  done = 0                            # Number of finished scans
  results: TableRef[string, ScanResult]  # Results of the scan (ip:data)

proc tryGetInfo(ip: string) {.async.} = 
  ## Checks if the Android Debug Bridge is hosted on a specified IP
  inc curWorkers
  var s = newAsyncSocket()
  
  try:
    let connectFut = s.connect(ip, Port(5555))
    # 5 seconds to connect
    if not await withTimeout(connectFut, 5000):
      return
    
    var msg = newConnectMsg()
    let sendFut = s.send(addr msg, sizeof(msg))
    # 2 seconds to send the connect packet
    if not await withTimeout(sendFut, 2000):
      return
    
    let reply = s.recvMessage()
    # 3.5 seconds to receive a reply
    if not await withTimeout(reply, 3500):
      return
    
    let replyMaybe = reply.read()
    # If device is "unauthorized" then we will not get "device"
    if replyMaybe.isSome() and "device" in replyMaybe.get().data:
      results[ip] = parsePayload(ip, replyMaybe.get().data)
  
  except:
    discard
  
  finally:
    inc done
    # Yes, this is ugly but that's required
    # because isClosed doesn't work reliably
    try:
      s.close()
    except:
      discard
    dec curWorkers

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

var allLen: int

proc updateBar() = 
  stdout.eraseLine()
  let perc = (100 * done / allLen).formatFloat(ffDecimal, 1)
  stdout.write &"{done} / {allLen} ({perc}%), found {results.len}"
  stdout.flushFile()

proc mainWork(ips: sink seq[string]) {.async.} = 
  allLen = ips.len

  # Preallocate some space
  results = newTable[string, ScanResult](allLen div 10)
  while true:
    updateBar()
    # No IPs left to scan -> exit the loop
    if ips.len == 0:
      break
    
    # While there are IPs left to scan and number of workers
    # is less than the maximum number of workers, create new workers
    while ips.len > 0 and curWorkers < maxWorkers:
      let ip = ips.pop()
      # Check if that IP is already known to have ADB running
      if ip notin results:
        asyncCheck tryGetInfo(ip)
    
    # Sleep 50ms so that we don't burn CPU cycles
    await sleepAsync(50)

proc writeText(f: File, results: TableRef[string, ScanResult]) = 
  for ip, res in results:
    f.writeLine(if res.name.len == 0:
      &"ip: {ip}, device info: {res.rawData}"
    else:
      &"ip: {ip} name: {res.name}, model: {res.model}, device: {res.device}, device info: {res.rawData}")

import std / json

proc writeJson(f: File, results: TableRef[string, ScanResult]) = 
  var root = newJArray()
  for ip, res in results:
    var obj = %*{
      "ip": ip,
      "name": res.name,
      "model": res.model,
      "device": res.device,
      "data": res.rawData
    }
    root.add obj
  f.write(root.pretty())

proc writeCsv(f: File, results: TableRef[string, ScanResult]) = 
  f.writeLine("IP,Name,Model,Device,RawData")
  for ip, res in results:
    # quote rawData since it may contain commas
    f.writeLine(&"{ip},{res.name},{res.model},{res.device},\"{res.rawData}\"")

proc cmdline(
  input = "ips.txt", output = "out.txt", 
  parseMode = PlainText, format = Auto, workers: Natural = 512, rescanCount: range[0..100] = 2
) =
  maxWorkers = workers

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

  var outType = format
  if outType == Auto:
    let tmp = output.rsplit(".", maxsplit = 1)
    if tmp.len == 2:
      let ext = tmp[1]
      case ext
      of "json": outType = Json
      of "csv": outType = Csv
      else: outType = Text
  
  var ips = parseFile(inputFile, parseMode)
  inputFile.close()

  # Add the same IPs for multiple rescans
  if rescanCount < 1:
    quit("You have to scan IPs at least once, right?")
  elif rescanCount > 1:
    ips = ips.cycle(rescanCount)
  
  # Randomize IPs
  randomize()
  ips.shuffle()

  waitFor mainWork(ips)
  
  # Wait until all requests complete (or time-out)
  while hasPendingOperations():
    poll()
  
  # Last update of the bar just for completeness
  updateBar()
  echo ""

  case outType
  of Csv: writeCsv(outfile, results)
  of Json: writeJson(outfile, results)
  of Text: writeText(outfile, results)
  else: discard

  outFile.flushFile()
  outFile.close()

proc main =
  # Use cligen to generate all command-line arguments with custom help
  dispatch(
    cmdline, 
    help = {
      "input": "Input file",
      "output": "Output file",
      "parseMode": "Input file format: PlainText (default), Masscan",
      "workers": "Amount of workers to use",
      "rescanCount": "Amount of requests to be sent to a single IP (1 for a single scan)",
      "format": "Format of the output file: Auto (based on the filename), Plain, Json, Csv"
    }
  )

main()