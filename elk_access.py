#!env /usr/bin/python
"""Access the elk M1 via the ethernet XEP module.

When an alarm state changes, requests the zone the changed.

Loosly based on the elkm1py code from:

https://github.com/sbelectronics/pi-controller
"""

import ast
import logging
import socket
import ssl
import sys
import time
import traceback

DISARM = 0
ARM_AWAY = 1
ARM_STAY = 2
ARM_STAY_INSTANT = 3
ARM_NIGHT = 4
ARM_NIGHT_INSTANT = 5
ARM_VACATION = 6
ARM_NEXT_AWAY = 7
ARM_NEXT_STAY = 8

ARM_UP_NOT_READY = 0
ARM_UP_READY = 1
ARM_UP_READY_FORCE = 2
ARM_UP_EXIT = 3
ARM_UP_FULLY = 4
ARM_UP_FORCE = 5
ARM_UP_BYPASS =6

ALARM_INACTIVE = '0'
ALARM_ENTRACE_DELAY = '1'
ALARM_ABORT_DELAY = '2'
ALARM_FIRE = '3'
ALARM_MEDICAL = '4'
ALARM_POLICE = '5'
ALARM_BURGLAR = '6'
ALARM_AUX1 = '7'
ALARM_AUX2 = '8'
ALARM_AUX3 = '9'
ALARM_AUX4 = ':'
ALARM_CO = ';'
ALARM_EMERGENCY = '<'
ALARM_FREEZE = '='
ALARM_GAS = '>'
ALARM_HEAT = '?'
ALARM_WATER = '@'
ALARM_FIRESUPER = 'A'
ALARM_FIREVERIFY = 'B'

ZONE_STATUS_NORMAL_UNC = "0"
ZONE_STATUS_NORMAL_OPEN = "1"
ZONE_STATUS_NORMAL_EOL = "2"
ZONE_STATUS_NORMAL_SHORT = "3"
ZONE_STATUS_NOT_USED_1 = "4"
ZONE_STATUS_TROUBLE_OPEN = "5"
ZONE_STATUS_TROUBLE_EOL = "6"
ZONE_STATUS_TROUBLE_SHORT = "7"
ZONE_STATUS_NOT_USED_2 = "8"
ZONE_STATUS_VIOLATED_OPEN = "9"
ZONE_STATUS_VIOLATED_EOL = "A"
ZONE_STATUS_VIOLATED_SHORT = "B"
ZONE_STATUS_NOT_USED_3 = "C"
ZONE_STATUS_BYPASSED_OPEN = "D"
ZONE_STATUS_BYPASSED_EOL = "E"
ZONE_STATUS_BYPASSED_SHORT = "F"

ZONE_STATUS = {
    ZONE_STATUS_NORMAL_UNC: "unconfigured",
    ZONE_STATUS_NORMAL_OPEN: "normal open",
    ZONE_STATUS_NORMAL_EOL: "normal eol",
    ZONE_STATUS_NORMAL_SHORT: "normal short",
    ZONE_STATUS_NOT_USED_1: "unused1",
    ZONE_STATUS_TROUBLE_OPEN: "trouble open",
    ZONE_STATUS_TROUBLE_EOL: "trouble eol",
    ZONE_STATUS_TROUBLE_SHORT: "trouble short",
    ZONE_STATUS_NOT_USED_2: "unused2",
    ZONE_STATUS_VIOLATED_OPEN: "violated open",
    ZONE_STATUS_VIOLATED_EOL: "violated eol",
    ZONE_STATUS_VIOLATED_SHORT: "violated short",
    ZONE_STATUS_NOT_USED_3: "unused3",
    ZONE_STATUS_BYPASSED_OPEN: "bypassed open",
    ZONE_STATUS_BYPASSED_EOL: "bypassed eol",
    ZONE_STATUS_BYPASSED_SHORT: "bypassed short",
}

DEFAULT_IP = "192.168.1.2"
DEFAULT_PORT = 2601
DEFAULT_CODE = 0000

VERSION_REQ = "vn"
VERSION_RESP = "VN"

LOG_REQ = "ld"
LOG_RESP = "LD"

ALARM_ZONE_REQ = "az"
ALARM_ZONE_RESP = "AZ"

ZONE_CHANGED_RESP = "ZC"

ARM_STATUS_REQ = "as"
ARM_STATUS_RESP = "AS"

XEP_REQ = "xk"
XEP_RESP = "XK"


class ElkAccess:
  def __init__(self, address=None, port=None):
    f = open("elkrc","r")
    setup = "".join(f.readlines())
    f.close()
    logging.info("elkrc: %s", setup)

    # elkrc is a textual python dictionary, so safely parse it
    # and turn it into an actual dictionary.
    self.values = ast.literal_eval(setup)
    logging.info("values: %s", self.values)

    # must have a username and password
    self.username = self.values["username"]
    self.password = self.values["password"]

    # but other things are optional
    self.code = self.values.get("code", DEFAULT_CODE)

    # passed in values override elkrc values
    if address:
      self.address = address
    else:
      self.address = self.values.get("address", DEFAULT_IP)

    if port:
      self.port = port
    else:
      self.port = int(self.values.get("port", DEFAULT_PORT))


    self.socket_connected = False
    self.seen_connected = False
    self.sent_password = False
    self.buf = ''
    if address is not None:
      self.connect()

  def connect(self):
    self.socket_connected = False
    self.seen_connected = False
    self.sent_password = False
    self.buf = ''
    self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    self.s = ssl.wrap_socket(self.s, ssl_version=ssl.PROTOCOL_TLSv1)
    self.s.connect((self.address, self.port))
    self.socket_connected = True

  def connected(self):
    pass

  def stupid_dump(self):
    while True:
      data = self.s.read()
      if len(data)>0:
        print len(data), data

  def calc_checksum(self, msg):
    chk = 0
    for x in msg:
      chk = (chk + ord(x)) & 0xFF;
    chk = 0x100 - chk
    return "%02X" % chk

  def send_username(self):
    logging.info("sending username: %s", self.username)
    self.s.write("%s\015\012" % self.username)

  def send_password(self):
    logging.info("sending password: %s", self.password)
    self.s.write("%s\015\012" % self.password)
    self.sent_password = True

  def gen_request_arm(self):
    pkt = "06as00"
    pkt = pkt + self.calc_checksum(pkt)
    return pkt + "\015\012"

  def arm_state(self, arm_state, arm_up, alarm_state):
    print "arm_state", arm_state
    print "arm_up", arm_up
    print "alarm_state", alarm_state

  def ParseXep(self, msg_len, msg_type, sentence):
    if msg_len != "16":
      logging.error("Xep alive had wrong lenght: %s", msg_len)
      return
    seconds = sentence[4:6]
    minutes = sentence[6:8]
    hours = sentence[8:10]
    dow = sentence[10]
    day = sentence[11:13]
    month = sentence[13:15]
    year = sentence[15:17]
    dst = sentence[17]
    mode = sentence[18]
    disp = sentence[19]

    s = "%s/%s/%s %s:%s:%s dow: %s dst: %s mode: %s disp: %s" % (
        month, day, year, hours, minutes, seconds,
        dow, dst, mode, disp)
    print s

  def ParseZone(self, msg_len, msg_type, sentence):
    if msg_len != "D6":
      logging.error("zone had wrong lenght: %s", msg_len)
      return
    # last 2 characters are the checksum
    zones = sentence[4:-2]
    print "zones: ", len(zones), zones

  def ParseZoneChanged(self, msg_len, msg_type, sentence):
    if msg_len != "0A":
      logging.error("zone changed had wrong lenght: %s", msg_len)
      return
    # last 2 characters are the checksum
    zone = sentence[4:7]
    status = sentence[7]
    print "zone: %s status: %s (%s)" % (zone, ZONE_STATUS[status], status)

  def read_sentence(self, sentence):
    sentence = sentence[:-2]
    logging.info("sentence: %s", sentence)
    if len(sentence)<6:
        return

    msg_len = sentence[0:2]
    msg_type = sentence[2:4]

    if ((not self.seen_connected) and 
        (sentence.startswith("Elk-M1XEP: Login successful."))):
        # we saw a successful login message
        self.seen_connected = True
        self.connected()

#        if ((not self.seen_connected) and 
#            (self.sent_password or self.password==None)):
#            # we saw a sentence, and we sent our password
#            self.seen_connected = True
#            self.connected()

    if msg_type == ARM_STATUS_RESP:
      if len(sentence)<32:
        print "malformed sentence", sentence
      else:
        arm_status = sentence[4:12]
        arm_up = sentence[12:20]
        alarm_state = sentence[20:28]

        self.last_arm_state = [int(x) for x in arm_status]

        self.arm_state( [int(x) for x in arm_status],
                        [int(x) for x in arm_up],
                        [x for x in alarm_state] )
    elif msg_type == XEP_RESP:
      self.ParseXep(msg_len, msg_type, sentence)
    elif msg_type == ALARM_ZONE_RESP:
      self.ParseZone(msg_len, msg_type, sentence)
    elif msg_type == ZONE_CHANGED_RESP:
      self.ParseZoneChanged(msg_len, msg_type, sentence)
    else:
      pass

  def bufferize(self):
      self.buf='';
      while True:
        while not self.socket_connected:
          try:
            logging.info("ELK: (re)connecting")
            self.connect()
            logging.info("ELK: (re)connected")
          except Exception as e:
            logging.error("ELK: connection failed: %s", e)
            traceback.print_exc()

        try:
          self.bufferize_once()
        except Exception as e:
          logging.error("ELK: exception in bufferize_once: %s", e)
          logging.error("ELK: sleeping before reconnecting")
          # let's not hammer the Elk too hard if there is a problem.
          time.sleep(30)
          self.socket_connected = False
          traceback.print_exc()

  def bufferize_once(self):
    data = self.s.read()
    for char in data:
      self.buf = self.buf + char
      if self.buf.endswith("Username:"):
        self.send_username()
        self.buf=''
      elif self.buf.endswith("Password:"):
        self.send_password()
        self.buf=''
      elif self.buf.endswith("\015\012"):
        self.read_sentence(self.buf)
        self.buf=''

class ElkArmStatePrinter(ElkAccess):
  def __init__(self, address=None, port=None):
    ElkAccess.__init__(self, address, port)

  def connected(self):
    print "connected"
    self.s.write(self.gen_request_arm())

def checksum_test_pkt(pkt):
  correct_sum = pkt[-2:]
  pkt = pkt[:-2]

  chk = ElkAccess().calc_checksum(pkt)
  if (correct_sum != chk):
    print "checksum test fail, pkt=%s, correct_sum=%s, calc_sum=%s" % (pkt, correct_sum, chk)

def checksum_test():
  checksum_test_pkt("0DCV0100123003C")
  checksum_test_pkt("08cv0100FE")
  checksum_test_pkt("13TR01200726875000000")
  checksum_test_pkt("11KF01C200000000087")
  checksum_test_pkt("16KA12345678111111110081")

def main():
  logging.basicConfig(level=logging.INFO)
  elk = ElkArmStatePrinter()
  elk.bufferize()

if __name__ == "__main__":
  main()

# vim: ai:ts=2:sw=2:et
