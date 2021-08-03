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

msgCount = 0
aesKey = b'YELLOW SUBMARINEENIRAMBUS WOLLEY'
#Pick your own secret key ;-)
#32 bytes for AES256
hmacKey = b'\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b'
#Pick your own HMAC key ;-)
#20 bytes for SHA-224

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
  b=""
  while b=="":
    z=ser.read_until()
    b=z.decode().strip()
  print("Response: "+b)
  return b

def sendPacket():
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

def initModule(port):
  ser = serial.serial_for_url(port, 9600)
  # arg 1 is the serial port
  time.sleep(1)
  try:
    if ser.isOpen():
      print("\nReady\n===========\n")
      response = sendCmd(b'AT+NWM=0')
      # P2P Mode
      if response != "OK":
        sys.exit("Stopping here!")
      response = sendCmd(b'AT+P2P=865000000:10:125:0:8:22')
      # 865 MHz, SD 10, BW 7 (125 KHz), CR 4/5, 8-byte preamble, TxPower 22
      if response != "OK":
        sys.exit("Stopping here!")
      response = sendCmd(b'AT+PRECV=0')
      # we won't be receiving anything
      if response != "OK":
        sys.exit("Stopping here!")
      time.sleep(1)
      sendPacket()
      # send a packet first
    while True:
      for i in range(0,60):
        # 60 1-second delays
        # check whether there's anything incoming from the serial port
        while ser.in_waiting:
          print(ser.readline())
        time.sleep(1)
      sendPacket()
      # and send a packet after 60 seconds
  
  except serial.SerialException as e:
    print("Exception")
    sys.stderr.write('could not open port {!r}: {}\n'.format(args.port, e))
    if ser.isOpen():
      ser.close()

if __name__ == "__main__":
  if len(sys.argv) < 1:
    print("Missing argument!")
    print("Usage:")
    print("python3 RAK3272S_Minimal_LoRa.py /dev/ttyUSB0")
    sys.exit("Leaving now")
  port = str(sys.argv[1])
  print("Starting with "+port)
  initModule(port)
