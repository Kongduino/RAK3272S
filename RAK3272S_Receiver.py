import json
import serial
import time
import sys
import binascii
import base64
from Crypto import Random
from Crypto.Cipher import AES
import datetime
import hmac

aesKey = b'YELLOW SUBMARINEENIRAMBUS WOLLEY'
#Pick your own secret key ;-)
#32 bytes for AES256
hmacKey = b'\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b'
#Pick your own HMAC key ;-)
#20 bytes for SHA-224

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
    if m.digest() == hm0:
      # compare the stated hmac with the hmac we just calculated
      print("HMAC passed!")
    else:
      print("HMAC failed!")
      print("--------------------------------------")
      print(bits[1])
      print("--------------------------------------")
      print(bits[1][:-56])
      print(binascii.hexlify(hm0).decode())
      print(m.hexdigest())
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

ser = serial.serial_for_url(str(sys.argv[1]), 9600)
time.sleep(0.1)
try:
  if ser.isOpen():
    print("\nReady\n===========\n")
    response = sendCmd(b'AT+NWM=0')
    if response != "OK":
      sys.exit("Stopping here!")
    response = sendCmd(b'AT+P2P=868125000:10:125:0:8:22')
    if response != "OK":
      sys.exit("Stopping here!")
    response = sendCmd(b'AT+PRECV=65535')
    # set to listening forever, one line
    # once you receive a line it goes back to Tx mode
    # a bit stupid if you ask me
    if response != "OK":
      sys.exit("Stopping here!")
  while True:
    z=ser.read_until()
    evalLine(z)
    # read a line and evaluate it

except serial.SerialException as e:
  print("Exception")
  sys.stderr.write('could not open port {!r}: {}\n'.format(args.port, e))
  if ser.isOpen():
    ser.close()
