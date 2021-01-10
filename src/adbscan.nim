import asyncdispatch, asyncnet
import strutils, strscans, strformat, sequtils
import terminal
import random

import cligen

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
  if (await s.recvInto(addr result, 24)) != 24:
    raise newException(ValueError, "Expected 24 bytes!")
  
  if result.magic != CmdConnectMagic or result.dataLen >= 1000:
    raise newException(ValueError, "Invalid data!")
  
  if result.dataLen > 0:
    result.data = await s.recv(int(result.dataLen))
  
  var crc = 0'u32
  for c in result.data:
    crc += uint32(ord(c))
  
  if crc != result.dataCrc32:
    raise newException(ValueError, "crc32 doesn't match!")


proc parsePayload(ip, data: string): string =
  var tmp, name, model, device: string
  # device::http://ro.product.name =starltexx;ro.product.model=SM-G960F;ro.product.device=starlte;features=cmd,stat_v2,shell_v2
  const scanStr = "device::$+ro.product.name$+=$+;ro.product.model=$+;ro.product.device=$+;"
  # This parsing is optional
  if scanf(data, scanStr, tmp, tmp, name, model, device):
    result = &"ip: {ip} name: {name}, model: {model}, device: {device}"
  else:
    result = &"ip: {ip} device info: {data}"

var 
  maxWorkers = 0        # Maximum number of allowed workers
  curWorkers = 0        # Current amount of workers
  done = 0              # Number of finished scans
  infoData: seq[string] # Results of the scan

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
    
    let replyData = reply.read().data
    # If device is "unauthorized" then we will not get this
    if "device" in replyData:
      infoData.add parsePayload(ip, replyData)
  
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
  # I know this isn't the smartest way but it should work :D
  # This is here just because we want to show stats which the user would
  # actually expect, because otherwise you can get 30 good results for 10 IPs
  infoData = infoData.deduplicate()
  stdout.write &"{done} / {allLen} ({perc}%), found {infoData.len}"
  stdout.flushFile()

proc mainWork(ips: sink seq[string]) {.async.} = 
  allLen = ips.len
  # Preallocate some space
  infoData = newSeqOfCap[string](allLen)
  while true:
    asyncCheck updateBar()
    # No IPs left to scan -> exit the loop
    if ips.len == 0:
      break
    # While there are IPs left to scan and number of workers
    # is less than the maximum number of workers, create new workers
    while ips.len > 0 and curWorkers < maxWorkers:
      # Randomization :P
      let i = rand(0 ..< ips.len)
      let ip = ips[i]
      ips.del(i)
      asyncCheck tryGetInfo(ip)
    # Sleep 50ms so that we don't burn CPU cycles
    await sleepAsync(50)

proc cmdline(
  input = "ips.txt", output = "out.txt", 
  parseMode = Masscan, workers = 512, rescanCount = 2
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
  
  var ips = parseFile(inputFile, parseMode)
  # Add the same IPs multiple times for scanning since they'll
  # be chosen at random later anyway
  if rescanCount > 0:
    ips = ips.cycle(rescanCount + 1)
  
  inputFile.close()
  
  waitFor mainWork(ips)
  
  # Wait until all requests complete (or timeout)
  while hasPendingOperations():
    poll()
  
  # Last update of the bar just for completeness
  waitFor updateBar()
  echo ""

  for res in infoData:
    outFile.writeLine(res)
  
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
      "workers": "Amount of workers to use",
      "rescanCount": "Amount of requests to be sent to a single IP (0 for no rescans)"
    }
  )

main()