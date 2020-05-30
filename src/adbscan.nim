import asyncdispatch, asyncnet
import strutils, strscans, strformat
import terminal

import cligen

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

proc recvMessage(s: AsyncSocket): Future[Message] {.async.} = 
  ## Receives an ADB Message over a socket
  discard await s.recvInto(addr result, 24)
  if result.magic != CmdConnectMagic or result.dataLen >= 1000:
    raise newException(ValueError, "Invalid data!")
  
  if result.dataLen > 0:
    result.data = await s.recv(int(result.dataLen))


proc parsePayload(data: string): string =
  var name, model, device: string
  const scanStr = "device::ro.product.name=$+;ro.product.model=$+;ro.product.device=$+;"
  if scanf(data, scanStr, name, model, device):
    result = &"name: {name}, model: {model}, device: {device}" 

var maxWorkers = 0        # Maximum number of allowed workers
var curWorkers = 0        # Current amount of workers
var done = 0              # Number of finished scans
var infoData: seq[string] # Results of the scan

proc tryGetInfo(ip: string) {.async.} = 
  ## Checks if the Android Debug Bridge is hosted on a specified IP
  inc curWorkers
  var s = newAsyncSocket()
  
  try:
    let connectFut = s.connect(ip, Port(5555))
    if not await withTimeout(connectFut, 5000):
      return
    
    var msg = newConnectMsg()
    let sendFut = s.send(addr msg, sizeof(msg))
    if not await withTimeout(sendFut, 2000):
      return
    
    let reply = s.recvMessage()
    if not await withTimeout(reply, 3500):
      return
    
    let replyData = reply.read().data
    # If device is "unauthorized" then we will not get this
    if "device" in replyData:
      infoData.add parsePayload(replyData)
  
  except:
    discard
  
  finally:
    inc done
    # Yes, this is ugly but that's required because isClosed didn't work reliably
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

proc updateBar() {.async.} = 
  stdout.eraseLine()
  let perc = (100 * done / allLen).formatFloat(precision = 3)
  stdout.write &"{done} / {allLen} ({perc}%), found {infoData.len}"
  stdout.flushFile()

proc mainWork(ips: sink seq[string]) {.async.} = 
  allLen = ips.len
  # Preallocate some space
  infoData = newSeqOfCap[string](allLen div 4)
  while true:
    asyncCheck updateBar()
    # No IPs left to scan -> exit the loop
    if ips.len == 0:
      break
    # While there are IPs left to scan and number of workers
    # is less than the maximum number of workers, create new workers
    while ips.len > 0 and curWorkers < maxWorkers:
      let ip = ips.pop()
      asyncCheck tryGetInfo(ip)
    # Sleep 50ms so that we don't burn CPU cycles
    await sleepAsync(50)

proc cmdline(input = "ips.txt", output = "out.txt", parseMode = Masscan, workers = 256) = 
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
  
  let ips = parseFile(inputFile, parseMode)
  inputFile.close()
  
  waitFor mainWork(ips)
  
  # Wait until all requests complete (or timeout)
  while hasPendingOperations():
    poll()
  
  # Last update of the bar just for completeness
  waitFor updateBar()
  echo ""
  
  for i, res in infoData:
    if res == "": continue
    outFile.writeLine(&"ip: {ips[i]} {res}")
  
  outFile.flushFile()
  outFile.close()

proc main =
  # Use cligen to generate all command-line arguments with custom help
  dispatch(
    cmdline, 
    help = {
      "input": "Input file",
      "output": "Output file",
      "parseMode": "Input file format: Masscan, PlainText",
      "workers": "Amount of workers to use"
    }
  )

main()