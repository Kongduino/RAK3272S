import json
import time
import sys
import binascii
import datetime
import uuid
import hmac
#from pathlib import Path
import select
#from Crypto import Random
from Crypto.Cipher import AES
import serial

msgCount = 0
needAES = 1
aesKey = b'YELLOW SUBMARINEENIRAMBUS WOLLEY'
#Pick your own secret key ;-)
#32 bytes for AES256
hmacKey = b'\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b'
#Pick your own HMAC key ;-)
#20 bytes for SHA-224
ser = ""
freq = 865.0
sf = 10
bw = 125
pre = 8
tx = 22
cr = 5
autoSend = 1
autoFreq = 60
needHMAC = 1
pongback = 0
snr = 0
rcvRSSI = 0
prefsFile = "prefs.json"
logsFile = ""

def hexDump(buf, length):
  s = "|"
  t = "| |"
  print("\n   +------------------------------------------------+ +----------------+")
  print("   |.0 .1 .2 .3 .4 .5 .6 .7 .8 .9 .a .b .c .d .e .f | |                |")
  print("   +------------------------------------------------+ +----------------+")
  i = 0
  while i<length:
    j=0
    while j<16:
      n= i + j
      if n >= length:
        s = s + "   "
        t = t + " "
      else:
        try:
          c = ord(buf[n])
        except KeyError:
          print("n = "+str(n))
          print("char = "+buf[n])
          sys.exit(s+t)
        a = '0'+(hex(c)[2:])
        s = s + a[len(a)-2:] + " "
        if (c < 32) | (c > 127):
          t = t + "."
        else:
          t = t + buf[n]
      j = j + 1
    ix = int(i / 16)
    if ix>15:
      print(hex(ix)[2:]+'.'+s + t + "|")
    else:
      print(" "+hex(ix)[2:]+'.'+s + t + "|")
    s = "|"; t = "| |";
    i = i + 16
  print("   +------------------------------------------------+ +----------------+")

def calcMaxPayload():
  mpl = -1
  if sf == 7:
    if (bw == 125) | (bw == 250):
      mpl = 222
  if sf == 8:
    if bw == 125:
      mpl = 222
  if sf == 9:
    if bw == 125:
      mpl = 115
  if ((sf == 10) | (sf == 11) | (sf == 12)) & (bw == 125):
    mpl = 51
  return mpl

def getUUID():
  return str(uuid.uuid4()).split('-')[0]
  # Short UUID for testing. You should use a longer one.

devName = "RAK3272S_"+getUUID()
# So that you can run several instances from the same directory

def savePrefs():
  global devName, freq, sf, bw, pre, cr, tx, needHMAC, autoSend, autoFreq, pongback, needAES, prefsFile, logsFile
  a = {}
  a["devName"] = devName
  a["freq"] = freq
  a["sf"] = sf
  a["bw"] = bw
  a["pre"] = pre
  a["tx"] = tx
  a["cr"] = cr
  if autoSend == 0:
    a["ap"] = 0
  else:
    a["ap"] = autoFreq
  a["hm"] = needHMAC
  a["aes"] = needAES
  a["pb"] = pongback
  print("Opening file "+prefsFile)
  f = open(prefsFile,'w')
  json.dump(a, f)
  print("Prefs file "+prefsFile+" written.")
  f = open(logsFile,'a')
  dt = datetime.datetime.now()
  f.write("Datetime: " + dt.strftime('%Y/%m/%d %H:%M:%S')+"\n")
  f.write("  Prefs file "+prefsFile+" written.\n")
  f.write(" . devName = "+devName+"\n")
  f.write(" . freq = "+str(freq)+"\n")
  f.write(" . sf = "+str(sf)+"\n")
  f.write(" . bw = "+str(bw)+"\n")
  f.write(" . pre = "+str(pre)+"\n")
  f.write(" . tx = "+str(tx)+"\n")
  f.write(" . cr = "+str(cr)+"\n")
  if autoSend == 0:
    f.write(" . ap = 0\n")
  else:
    f.write(" . ap = "+str(autoFreq)+"\n")
  f.write(" . hm = "+str(needHMAC)+"\n")
  f.write(" . aes = "+str(needAES)+"\n")
  f.write(" . pb = "+str(pongback)+"\n")
  f.close()

def packOptions():
  fq = int(freq * 1e6)
  opt = str(fq)+":"+str(sf)+":"+str(bw)+":"+str(cr-5)+":"+str(pre)+":"+str(tx)
  mpl = calcMaxPayload()
  if mpl > -1:
    print("Max payload: "+str(mpl)+" bytes")
  else:
    print("Invalid SF/BW for payload!")
  return b'AT+P2P='+str.encode(opt)

def displayOptions():
  print(" . Freq: "+str(freq)+" MHz")
  print(" . Device name: "+str(devName))
  print(" . SF: "+str(sf))
  print(" . BW: "+str(bw) + " KHz")
  print(" . Preamble: "+str(pre))
  print(" . CR: 4/"+str(cr))
  print(" . Tx: "+str(tx))
  if needAES == 1:
    print(" . AES required")
  else:
    print(" . AES not required")
  if needHMAC == 1:
    print(" . HMAC required")
  else:
    print(" . HMAC not required")
  if autoSend == 1:
    print(" . autoSend: every "+str(autoFreq)+"s")
  else:
    print(" . No auto ping")
  if pongback == 1:
    print(" . PONG back ON")
  else:
    print(" . PONG back OFF")

def readPrefs(fileName):
  global devName, freq, sf, bw, pre, cr, tx, needHMAC, autoSend, autoFreq, pongback, needAES, logsFile
  try:
    # Open JSON file
    print("Opening file "+fileName)
    f = open(fileName,'r')
  except FileNotFoundError:
    print("No preferences file. Processing with defaults")
    return
  print("Loading preferences")
  # returns JSON object as a dictionary
  try:
    x = json.load(f)
  except ValueError:  # includes simplejson.decoder.JSONDecodeError
    print("--------------------------------------")
    print("Decoding JSON has failed. Is this JSON? I don't think it is JSON.")
    print("--------------------------------------")
    return
  if x.get('sf') is not None:
    sf = x['sf']
  if x.get('bw') is not None:
    bw = x['bw']
  if x.get('freq') is not None:
    freq = x['freq']
  if x.get('pre') is not None:
    pre = x['pre']
  if x.get('cr') is not None:
    cr = x['cr']
  if x.get('tx') is not None:
    tx = x['tx']
  if x.get('aes') is not None:
    needAES = x['aes']
  if x.get('hm') is not None:
    needHMAC = x['hm']
  if x.get('pb') is not None:
    pongback = x['pb']
  if x.get('devName') is not None:
    devName = x['devName']
  autoping = 0
  if x.get('ap') is not None:
    autoping = x['ap']
    if autoping == 0:
      autoSend = 0
    else:
      autoSend = 1
      autoFreq = autoping
  f = open(logsFile,'a')
  dt = datetime.datetime.now()
  f.write("Datetime: " + dt.strftime('%Y/%m/%d %H:%M:%S')+"\n")
  f.write("  Read prefs file "+prefsFile+".\n")
  f.close()
  displayOptions()

def buildPacket(msg):
  global msgCount
  a = {}
  a['from'] = devName
  a['cmd'] = "msg"
  a['UUID'] = getUUID()
  a['msg'] = msg
  return a

def buildAutoPacket():
  global msgCount
  a = buildPacket("Message #"+str(msgCount))
  msgCount += 1
  return a

def buildPongPacket(UUID):
  global snr, rcvRSSI
  a = {}
  a['from'] = devName
  a['cmd'] = "pong"
  a['UUID'] = UUID
  a['rcvRSSI'] = int(rcvRSSI)
  return a

def sendPing():
  packet = buildAutoPacket()
  # create a dict with an auto-generated message
  sendPacket(packet)
  # and send a packet

def sendCmd(cmd, ignore = True, showCmd = True):
  ser.write(cmd)
  ser.write(b'\r\n')
  if showCmd == True:
    print(cmd.decode())
  time.sleep(1.0)
  b=b''
  if ignore == False:
    while b==b'':
      z=ser.read_until()
      b=z.strip()
    if b != b'OK':
      print(b"Response: `"+b+b'`')
      sys.exit("Stopping here!")
  else:
    b=b'OK'
  return b

def sendPacket(packet):
  global logsFile
  print("sending packet")
  f = open(logsFile,'a')
  dt = datetime.datetime.now()
  f.write("Datetime: " + dt.strftime('%Y/%m/%d %H:%M:%S')+"\n")
  f.write("  Sent packet:\n  ")
  f.write(json.dumps(packet))
  f.write('\n')
  f.close()
  response = sendCmd(b'AT+PRECV=0', True, False)
  # stop listening
  time.sleep(1.0)
  packet=str.encode(json.dumps(packet))
  hexDump(packet.decode(), len(packet))
  # encode the dict as a JSON message
  if needAES == 1:
    cipher = AES.new(aesKey, AES.MODE_ECB)
    # create a cipher, AES256, ECB
    while len(packet)%16 !=0:
      packet=packet+b'\x00'
      # pad length to be a multiple of 16
      # Ideally the byte should be the number of missing bytes
      # I'll leave this to you :-)
    enc = cipher.encrypt(packet)
    # encrypt the packet
    if needHMAC == 1:
      m = hmac.new(hmacKey,b'',"sha224")
      # create a SHA-224 hmac object with a HMAC key
      m.update(enc)
      # pass the encrypted message
      jPacket = binascii.hexlify(enc+m.digest())
      # packet + HMAC hex-encoded
    else:
      jPacket = binascii.hexlify(enc)
    hexDump(jPacket.decode(), len(jPacket))
  else:
    jPacket = binascii.hexlify(packet)
    hexDump(packet, len(packet))
  response = sendCmd(b'AT+PSEND='+jPacket, True, False)
  print("packet sent!")
  time.sleep(1.0)
  response = sendCmd(b'AT+PRECV=65535', True, False)

def sendMsg(msg):
  packet = buildPacket(msg)
  print(packet)
  sendPacket(packet)

def sendPong(UUID):
  packet = buildPongPacket(UUID)
  #print(packet)
  sendPacket(packet)

def setHmac(arg):
  global needHMAC
  x = int(arg)
  if x == 0:
    needHMAC = 0
    displayOptions()
  elif x == 1:
    needHMAC = 1
    displayOptions()
  else:
    print("Bad argument: "+arg)

def setRP(arg):
  global pongback
  x = int(arg)
  if x == 0:
    pongback = 0
    displayOptions()
  elif x == 1:
    pongback = 1
    displayOptions()
  else:
    print("Bad argument: "+arg)

def setEnc(arg):
  global needAES
  x = int(arg)
  if x == 0:
    needAES = 0
    displayOptions()
  elif x == 1:
    needAES = 1
    displayOptions()
  else:
    print("Bad argument: "+arg)

def setCr(arg):
  global cr
  try:
    x=int(arg)
    if x not in range(5, 9):
      print("Error: "+str(x)+" isn't the in range [5..8]")
    else:
      cr = x
      response = sendCmd(packOptions())
      time.sleep(3)
      displayOptions()
  except ValueError:
    print("Bad argument: "+arg)

def setTx(arg):
  global tx
  try:
    x=int(arg)
    if x not in range(7, 23):
      print("Error: "+str(x)+" isn't the in range [7..22]")
    else:
      tx = x
      response = sendCmd(packOptions())
      time.sleep(3)
      displayOptions()
  except ValueError:
    print("Bad argument: "+arg)

def setBw(arg):
  global bw
  try:
    x=int(arg)
    if x not in range(7, 10):
      print("Error: "+str(x)+" isn't the in range [7..9]")
    else:
      bw = x
      response = sendCmd(packOptions())
      time.sleep(3)
      displayOptions()
  except ValueError:
    print("Bad argument: "+arg)

def setSf(arg):
  global sf
  try:
    x=int(arg)
    if x not in range(6, 11):
      print("Error: "+str(x)+" isn't the in range [6..10]")
    else:
      sf = x
      response = sendCmd(packOptions())
      time.sleep(3)
      displayOptions()
  except ValueError:
    print("Bad argument: "+arg)

def setFq(arg):
  global freq
  try:
    x=float(arg)
    if (x < 860.0) | (x > 1020.1):
      print("Error: "+str(x)+" isn't the in range [860..1,020]")
    else:
      freq = v
      response = sendCmd(packOptions())
      time.sleep(3)
      displayOptions()
  except ValueError:
    print("Bad argument: "+arg)

def setAs(arg):
  global autoSend, autoFreq
  try:
    x=int(arg)
    if x == 0:
      autoSend = 0
      autoFreq = 60
    else:
      autoSend = 1
      autoFreq = x
    displayOptions()
  except ValueError:
    print("Bad parameter: "+arg)

def setDeviceName(arg):
  global devName
  dn = arg.strip()
  if dn != "":
    devName = dn
    displayOptions()
  else:
    print("Empty device name!")

def setPwd(arg):
  global aesKey
  key = arg.strip()
  if len(key) == 32:
    aesKey = key.encode()
    displayOptions()
  elif len(key) == 64:
    try:
      key = binascii.unhexlify(a)
      aesKey = key
      displayOptions()
    except binascii.Error:
      print("Invalid 64-hex string!")
  else:
    print("Invalid string length!")
    print("Please pass either 32-byte plain key or 64-byte hex key")

def initModule(port):
  global ser
  global autoFreq
  if autoSend != 1:
    autoFreq = 60
  # if autoSend is off make that 60
  # used in the main loop
  try:
    ser = serial.serial_for_url(port, 9600, timeout = 10)
    # arg 1 is the serial port
  except serial.SerialException as e:
    sys.exit("/!\ Yo Dukie! Port not found! Aborting.")
  time.sleep(1)
  readPrefs(prefsFile)
  try:
    if ser.isOpen():
      print("\nReady\n===========\n")
      response = sendCmd(b'AT+NWM=0')
      # P2P Mode
      time.sleep(1.5)
      response = sendCmd(packOptions())
      time.sleep(3)
      response = sendCmd(b'AT+PRECV=65535')
      time.sleep(1.5)
  except serial.SerialException as e:
    print("Exception")
    sys.stderr.write('could not open port {!r}: {}\n'.format(args.port, e))
    if ser.isOpen():
      ser.close()

def displayValues(x):
  dt= datetime.datetime.now()
  print("Datetime: " + dt.strftime('%Y/%m/%d %H:%M:%S'))
  # Display date and time
  print("UUID: "+x["UUID"])
  print("from: "+x["from"])
  print("cmd: "+x["cmd"])
  # all packets have these 3.
  if x["cmd"] == "msg":
    print(x["msg"])
    return
  elif x["cmd"] == "ping":
    if pongback == 1:
      sendPong(x["UUID"])
  elif x["cmd"] == "pong":
    print("rcvRSSI: "+str(x["rcvRSSI"]))
    # A pong message in Minimal_LoRa sends back the RSSI at which it received a PING
  if x.get('H') is not None:
    print("Humidity: "+str(x["H"]))
  if x.get('T') is not None:
    print("Temperature: "+str(x["T"]))
  if x.get('V') is not None:
    print("tVOC: "+str(x["V"]))
  if x.get('C') is not None:
    print("CO2: "+str(x["C"]))

def evalLine(z):
  global snr, rcvRSSI, logsFile
  if z.startswith(b'+EVT:RXP2P'):
    # +EVT:RXP2P, RSSI: -xx, SNR: -yy
    bits = z.strip().split(b', ')
    snr = bits[2].split(b' ')[1]
    rcvRSSI = bits[1].split(b' ')[1]
    print("\n--------------------------------------")
    print((b'Incoming message at RSSI: '+rcvRSSI+b', SNR: '+snr).decode())
    f = open(logsFile,'a')
    dt = datetime.datetime.now()
    f.write("Datetime: " + dt.strftime('%Y/%m/%d %H:%M:%S')+"\n")
    f.write((b'  Incoming message at RSSI: '+rcvRSSI+b', SNR: '+snr+b'\n').decode())
    f.close()
  elif z.startswith(b'+EVT:'):
    # The message, hex encoded
    bits=z.strip().split(b':')
    #remove \r\n at the end (strip)
    if needHMAC == 1:
      try:
        hm0=binascii.unhexlify(bits[1][-56:])
        # the last 28 bytes = hmac
      except binascii.Error:
        print("Odd-length string in evalLine/unhexlify(hm0)")
        return
      m = hmac.new(hmacKey, b'', "sha224")
      # create an hmac object
      try:
        msg=binascii.unhexlify(bits[1][:-56])
        # msg is everything except the last 28 bytes
      except binascii.Error:
        print("Odd-length string in evalLine/unhexlify(msg)")
        return
      m.update(msg)
      # create a digest of the message
      cHMAC = m.hexdigest()
      try:
        oHMAC = binascii.hexlify(hm0).decode()
      except binascii.Error:
        print("Odd-length string in evalLine/unhexlify(oHMAC)")
        return
      if cHMAC == oHMAC:
        # compare the stated hmac with the hmac we just calculated
        print("HMAC passed!")
      else:
        print("HMAC failed!")
        print("--------------------------------------")
        print(bits[1][-56:])
        print(bits[1][:-56])
        print("--------------------------------------")
        print("Original HMAC: "+oHMAC)
        print("Calculated HMAC: "+cHMAC)
    else:
      #print("HMAC not needed, so msg = ")
      msg=binascii.unhexlify(bits[1])
      #print(msg)
    if needAES == 1:
      cipher = AES.new(aesKey, AES.MODE_ECB)
      # create a cipher, AES256, ECB
      dec=""
      try:
        dec = cipher.decrypt(msg)
        # decrypt the message
      except ValueError:
        print("Data must be aligned to block boundary in ECB mode")
        print("Len of msg is: "+str(len(msg)))
        return
    else:
      dec = msg
    try:
      dec=dec.split(b'}')[0]+b'}'
      # ugly hack to remove extra bytes after }
      f = open(logsFile,'a')
      dt = datetime.datetime.now()
      f.write("Datetime: " + dt.strftime('%Y/%m/%d %H:%M:%S')+"\n")
      f.write('  Received message:\n  ')
      f.write(dec.decode())
      f.write('\n')
      f.close()
      x=json.loads(dec)
      # parse JSON
      displayValues(x)
    except ValueError:  # includes simplejson.decoder.JSONDecodeError
      print("--------------------------------------")
      print("Decoding JSON has failed. Is this JSON? I don't think it is JSON.")
      print(msg)
    print("--------------------------------------")
    response = sendCmd(b'AT+PRECV=65535')
    # set back to listening

knownFunctions = [
  ["/p", sendPing, 0], ["/>", sendMsg, 1], ["/hm", setHmac, 1],
  ["/cr", setCr, 1], ["/tx", setTx, 1], ["/bw", setBw, 1],
  ["/sf", setSf, 1], ["/r", setRP, 1], ["/fq", setFq, 1],
  ["/as", setAs, 1], ["/e", setEnc, 1], ["/dn", setDeviceName, 1],
  ["/PW", setPwd, 1], ["/save", savePrefs, 0]
]

def testFn(line):
  # This function takes one line from user input
  # And looks for a know command (see above)
  # If the command requires no arguments, 3rd value
  # in the array is 0, and the Fn is called as is.
  # Or the remainder of the line is passed as argument.
  # eg:
  # '/p' PING, no argument need. ["/p", sendPing, 0]
  # '/fq' Set Frequency, frequency needs to be passed: ["/fq", setFq, 1]
  global knownFunctions
  for x in knownFunctions:
    if line.startswith(x[0]):
      if x[2] == 0:
        x[1]()
      else:
        param = line[len(x[0]):]
        x[1](param)
      return
  print("Unknown command!")

if __name__ == "__main__":
  if len(sys.argv) < 2:
    print("\n\n================================================================\nMissing argument! Usage:")
    print("> python3 RAK3272S_Minimal_LoRa.py /dev/ttyUSB0 [prefsfile.json]")
    sys.exit("Leaving now\n================================================================\n\n")
  port = str(sys.argv[1])
  print("Starting with "+port)
  if len(sys.argv) == 3:
    prefsFile = str(sys.argv[2])
  logsFile = "Log_"+getUUID()+".log"
  print(logsFile)
  initModule(port)
  f = open(logsFile,'w')
  dt = datetime.datetime.now()
  f.write("Datetime: " + dt.strftime('%Y/%m/%d %H:%M:%S')+"\n")
  f.write("  Created log file\n")
  f.close()
  while True:
    for i in range(0, autoFreq):
      # autoFreq x 1-second delays
      # 60 by default if autoSend is off
      # check whether there's anything incoming from the serial port
      dr,dw,de = select.select([sys.stdin], [], [], 0)
      if dr != []:
        # key press, read a line
        query = input().strip()
        #print("> "+query)
        testFn(query)
        # easier way to add commands
      while ser.in_waiting:
        z=ser.readline()
        evalLine(z)
      time.sleep(1)
    if autoSend == 1:
        sendPing()
