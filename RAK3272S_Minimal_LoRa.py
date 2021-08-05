import json
import serial
import time
import sys
import binascii
from Crypto import Random
from Crypto.Cipher import AES
import datetime
import uuid
import hmac
from pathlib import Path
import select

msgCount = 0
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

def getUUID():
  return str(uuid.uuid4()).split('-')[0]
  # Short UUID for testing. You should use a longer one.

devName = "RAK3272S_"+getUUID()
# So that you can run several instances from the same directory

def packOptions():
  fq = int(freq * 1e6)
  opt = str(fq)+":"+str(sf)+":"+str(bw)+":"+str(cr-5)+":"+str(pre)+":"+str(tx)
  return b'AT+P2P='+str.encode(opt)

def displayOptions():
  print(" . Freq: "+str(freq)+" MHz")
  print(" . Device name: "+str(devName))
  print(" . SF: "+str(sf))
  print(" . BW: "+str(bw) + " KHz")
  print(" . Preamble: "+str(pre))
  print(" . CR: 4/"+str(cr))
  print(" . Tx: "+str(tx))
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
  global devName, freq, sf, bw, pre, cr, tx, needHMAC, autoSend, autoFreq, pongback
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
  if x.get('sf') != None:
    sf = x['sf']
  if x.get('bw') != None:
    bw = x['bw']
  if x.get('freq') != None:
    freq = x['freq']
  if x.get('pre') != None:
    pre = x['pre']
  if x.get('cr') != None:
    cr = x['cr']
  if x.get('tx') != None:
    tx = x['tx']
  if x.get('hm') != None:
    needHMAC = x['hm']
  if x.get('pb') != None:
    pongback = x['pb']
  if x.get('devName') != None:
    devName = x['devName']
  autoping = 0
  if x.get('ap') != None:
    autoping = x['ap']
    if autoping == 0:
      autoSend = 0
    else:
      autoSend = 1
      autoFreq = autoping
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

def sendCmd(cmd, ignore = True):
  ser.write(cmd)
  ser.write(b'\r\n')
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
  response = sendCmd(b'AT+PRECV=0')
  # stop listening
  time.sleep(1.0)
  cipher = AES.new(aesKey, AES.MODE_ECB)
  # create a cipher, AES256, ECB
  packet=str.encode(json.dumps(packet))
  # encode the dict as a JSON message
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
  response = sendCmd(b'AT+PSEND='+jPacket)
  time.sleep(1.0)
  response = sendCmd(b'AT+PRECV=65535')

def sendMsg(msg):
  packet = buildPacket(msg)
  sendPacket(packet)

def sendPong(UUID):
  packet = buildPongPacket(UUID)
  #print(packet)
  sendPacket(packet)

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
  except FileNotFoundError as e:
    sys.exit("Port not found! Aborting.")
  time.sleep(1)
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
  if x.get('H') != None:
    print("Humidity: "+str(x["H"]))
  if x.get('T') != None:
    print("Temperature: "+str(x["T"]))
  if x.get('V') != None:
    print("tVOC: "+str(x["V"]))
  if x.get('C') != None:
    print("CO2: "+str(x["C"]))

def evalLine(z):
  global snr, rcvRSSI
  if z.startswith(b'+EVT:RXP2P'):
    # +EVT:RXP2P, RSSI: -xx, SNR: -yy
    bits = z.strip().split(b', ')
    snr = bits[2].split(b' ')[1]
    rcvRSSI = bits[1].split(b' ')[1]
    print((b'Incoming message at RSSI: '+rcvRSSI+b', SNR: '+snr).decode())
  elif z.startswith(b'+EVT:'):
    # The message, hex encoded
    bits=z.strip().split(b':')
    #remove \r\n at the end (strip)
    if needHMAC == 1:
      hm0=binascii.unhexlify(bits[1][-56:])
      # the last 28 bytes = hmac
      m = hmac.new(hmacKey, b'', "sha224")
      # create an hmac object
      msg=binascii.unhexlify(bits[1][:-56])
      # msg is everything except the last 28 bytes
      m.update(msg)
      # create a digest of the message
      cHMAC = m.hexdigest()
      oHMAC = binascii.hexlify(hm0).decode()
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
      print("HMAC not needed, so msg = ")
      msg=binascii.unhexlify(bits[1])
      print(msg)
    cipher = AES.new(aesKey, AES.MODE_ECB)
    # create a cipher, AES256, ECB
    dec=""
    try:
      dec=cipher.decrypt(msg)
      # decrypt the message
    except ValueError as e:
      print("Data must be aligned to block boundary in ECB mode")
      print("Len of msg is: "+str(len(msg)))
    try:
      msg=dec.split(b'}')[0]+b'}'
      # ugly hack to remove extra bytes after }
      x=json.loads(msg)
      # parse JSON
      displayValues(x)
    except ValueError:  # includes simplejson.decoder.JSONDecodeError
      print("--------------------------------------")
      print("Decoding JSON has failed. Is this JSON? I don't think it is JSON.")
      print(msg)
    print("--------------------------------------")
    response = sendCmd(b'AT+PRECV=65535')
    # set back to listening

if __name__ == "__main__":
  if len(sys.argv) < 2:
    print("\n\n================================================================\nMissing argument! Usage:")
    print("> python3 RAK3272S_Minimal_LoRa.py /dev/ttyUSB0 [prefsfile.json]")
    sys.exit("Leaving now\n================================================================\n\n")
  port = str(sys.argv[1])
  print("Starting with "+port)
  pFile = "prefs.json"
  if len(sys.argv) == 3:
    pFile = str(sys.argv[2])
  readPrefs(pFile)
  initModule(port)
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
        if query[0:2] == "/>":
          sendMsg(query[2:])
        elif query == "/p":
          sendPing()
        elif query == "/hm0":
          needHMAC = 0
          displayOptions()
        elif query == "/hm1":
          needHMAC = 1
          displayOptions()
        elif query == "/r0":
          pongback = 0
          displayOptions()
        elif query == "/r1":
          pongback = 1
          displayOptions()
        elif query[0:3] == "/as":
          try:
            v=int(query[3:])
            if v == 0:
              autoSend = 0
              autoFreq = 60
            else:
              autoSend = 1
              autoFreq = v
            displayOptions()
          except ValueError:
            print("Bad parameter: "+query[3:])
        elif query[0:3] == "/cr":
          try:
            v=int(query[3:])
            if v not in range(5, 9):
              print("Error: "+str(v)+" isn't the in range [5..8]")
            else:
              cr = v
              response = sendCmd(packOptions())
              time.sleep(3)
              displayOptions()
          except ValueError:
            print("Bad parameter: "+query[3:])
        elif query[0:3] == "/tx":
          try:
            v=int(query[3:])
            if v not in range(7, 23):
              print("Error: "+str(v)+" isn't the in range [7..22]")
            else:
              tx = v
              response = sendCmd(packOptions())
              time.sleep(3)
              displayOptions()
          except ValueError:
            print("Bad parameter: "+query[3:])
        elif query[0:3] == "/fq":
          try:
            v=float(query[3:])
            if (v < 860.0) | (v > 1020.0):
              print("Error: "+str(v)+" isn't the in range [860..1,020]")
            else:
              freq = v
              response = sendCmd(packOptions())
              time.sleep(3)
              displayOptions()
          except ValueError:
            print("Bad parameter: "+query[3:])
      while ser.in_waiting:
        z=ser.readline()
        evalLine(z)
      time.sleep(1)
    if autoSend == 1:
        sendPing()
