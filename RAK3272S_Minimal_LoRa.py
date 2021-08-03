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

def packOptions():
  fq = int(freq * 1e6)
  opt = str(fq)+":"+str(sf)+":"+str(bw)+":"+str(cr-5)+":"+str(pre)+":"+str(tx)
  return b'AT+P2P='+str.encode(opt)

def readPrefs(fileName):
  try:
    # Open JSON file
    f = open(fileName,)
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
    print("SF: "+str(x['sf']))
    sf = x['sf']
  if x.get('bw') != None:
    print("BW: "+str(x['bw']))
    bw = x['bw']
  if x.get('freq') != None:
    print("Freq: "+str(x['freq']))
    freq = x['freq']
  if x.get('pre') != None:
    print("Preamble: "+str(x['pre']))
    pre = x['pre']
  if x.get('cr') != None:
    print("CR: "+str(x['cr']))
    cr = x['cr']
  if x.get('tx') != None:
    print("Tx: "+str(x['tx']))
    tx = x['tx']

def getUUID():
  return str(uuid.uuid4()).split('-')[0]
  # Short UUID for testing. You should use a longer one.

def buildPacket():
  global msgCount
  a = {}
  a['from'] = "RAK3272Sender"
  a['cmd'] = "msg"
  a['UUID'] = getUUID()
  a['msg'] = "Message #"+str(msgCount)
  msgCount += 1
  return a

def sendCmd(cmd):
  ser.write(cmd)
  ser.write(b'\r\n')
  print(cmd.decode())
  time.sleep(1.0)
  b=""
  while b=="":
    z=ser.read_until()
    b=z.decode().strip()
  if b != "OK":
    print("Response: "+b)
    sys.exit("Stopping here!")
  return b

def sendPacket():
  response = sendCmd(b'AT+PRECV=0')
  # stop listening
  time.sleep(1.0)
  cipher = AES.new(aesKey, AES.MODE_ECB)
  # create a cipher, AES256, ECB
  packet = buildPacket()
  # create a dict
  packet=str.encode(json.dumps(packet))
  # encode the dict as a JSON message
  while len(packet)%16 !=0:
    packet=packet+b'\x00'
    # pad length to be a multiple of 16
    # Ideally the byte should be the number of missing bytes
    # I'll leave this to you :-)
  enc = cipher.encrypt(packet)
  # encrypt the packet
  m = hmac.new(hmacKey,b'',"sha224")
  # create a SHA-224 hmac object with a HMAC key
  m.update(enc)
  # pass the encrypted message
  jPacket = binascii.hexlify(enc+m.digest())
  # packet + HMAC hex-encoded
  response = sendCmd(b'AT+PSEND='+jPacket)
  time.sleep(1.0)
  response = sendCmd(b'AT+PRECV=65535')

def initModule(port):
  global ser
  global autoFreq
  if autoSend != 1:
    autoFreq = 60
  # if autoSend is off make that 60
  # used in the main loop
  ser = serial.serial_for_url(port, 9600)
  # arg 1 is the serial port
  time.sleep(1)
  try:
    if ser.isOpen():
      print("\nReady\n===========\n")
      response = sendCmd(b'AT+NWM=0')
      # P2P Mode
      time.sleep(1.5)
      response = sendCmd(packOptions())
      # 865 MHz, SD 10, BW 7 (125 KHz), CR 4/5, 8-byte preamble, TxPower 22
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
  if z.startswith(b'+EVT:RXP2P'):
    # +EVT:RXP2P, RSSI: -xx, SNR: -yy
    bits=z.strip().split(b', ')
    print((b'Incoming message at '+bits[1]+b', '+bits[2]).decode())
  elif z.startswith(b'+EVT:'):
    # The message, hex encoded
    bits=z.strip().split(b':')
    #remove \r\n at the end (strip)
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
    cipher = AES.new(aesKey, AES.MODE_ECB)
    # create a cipher, AES256, ECB
    dec=""
    dec=cipher.decrypt(msg)
    # decrypt the message
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
    print("\n\n============================================\nMissing argument! Usage:")
    print("> python3 RAK3272S_Minimal_LoRa.py /dev/ttyUSB0")
    sys.exit("Leaving now\n============================================\n\n")
  port = str(sys.argv[1])
  print("Starting with "+port)
  readPrefs("./prefs.json")
  initModule(port)
  while True:
    for i in range(0, autoFreq):
      # autoFreq x 1-second delays
      # 60 by default if autoSend is off
      # check whether there's anything incoming from the serial port
      dr,dw,de = select.select([sys.stdin], [], [], 0)
      if dr != []:
        # key press, read a line
        query = input()
        print("> "+query)
      while ser.in_waiting:
        z=ser.readline()
        evalLine(z)
      time.sleep(1)
    if autoSend == 1:
      sendPacket()
      # and send a packet after autoFreq seconds
