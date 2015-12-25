#!env /usr/bin/python
""" Create the table for holding alarm data.
"""

import datetime
import os
import sqlite3
import sys
import time

CREATE_CMD = """
CREATE TABLE reason (
  timestampms INTEGER PRIMARY KEY NOT NULL,
  zone INTEGER,
  status INTEGER,
  definition INTEGER,
  armed INTEGER,
  armup INTEGER,
  alarm TEXT,
  actual TEXT,
  isodate TEXT
  );
""" 

INSERT_CMD = """
INSERT INTO reason VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?);
""" 
FNAME_PREFIX = "alarm"

class SaveToSql(object):

  def __init__(self, prefix=None):
    if prefix:
      self._prefix = prefix
    else:
      self._prefix = FNAME_PREFIX

  def CreateIfNeeded(self):
    """Create the sql database if it doesn't already exist."""
    # we want one database per week for now to keep the data from
    # growing too big for sqlite. Format is YYYY_WW where YYYY
    # is the 4 digit year and WW is the 2 digit week number
    isocal = datetime.date.isocalendar(datetime.datetime.utcnow())
    dt = "%04d_%02d" % (isocal[0], isocal[1])
    self._fname = "%s_%s.sqlite3" % (self._prefix, dt)

    if not os.access(self._fname, os.F_OK):
      con = sqlite3.connect(self._fname)
      with con:
        cur = con.cursor()
        cur.execute(CREATE_CMD)
        con.commit()


  def StoreZone(self, timestampms, zone, status, definition,
      armed, armup, alarm, actual):
    l = time.gmtime(timestampms / 1000.0)
    dt = time.strftime("%Y-%m-%dT%H:%M:%S", l)
    con = sqlite3.connect(self._fname)
    with con:
      cur = con.cursor()
      cur.execute(INSERT_CMD,
          (int(timestampms), int(zone), int(status), int(definition),
           int(armed), int(armup), alarm,
           actual, dt))
      con.commit()

if __name__ == "__main__":
  sys.exit("Intended for import, not execution")

