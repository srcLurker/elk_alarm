#!env /usr/bin/python
""" Create the table for holding alarm data.
"""

import sqlite3
import os
import sys
import time

CREATE_CMD = """
CREATE TABLE reason (
  timestampms INTEGER PRIMARY KEY NOT NULL,
  zone INTEGER,
  status INTEGER,
  actual TEXT,
  isodate TEXT
  );
""" 

INSERT_CMD = """
INSERT INTO reason VALUES(?, ?, ?, ?, ?);
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
    now = time.time()
    l = time.gmtime(now)
    dt = time.strftime("%a_%Y%m%d", l)
    self._fname = "%s_%s.sqlite3" % (self._prefix, dt)

    if not os.access(self._fname, os.F_OK):
      con = sqlite3.connect(self._fname)
      with con:
        cur = con.cursor()
        cur.execute(CREATE_CMD)
        con.commit()


  def StoreZone(self, timestampms, zone, status, actual):
    l = time.gmtime(timestampms / 1000.0)
    dt = time.strftime("%Y-%m-%dT%H:%M:%S", l)
    con = sqlite3.connect(self._fname)
    with con:
      cur = con.cursor()
      cur.execute(INSERT_CMD,
          (int(timestampms), int(zone), int(status), actual, dt))
      con.commit()

if __name__ == "__main__":
  sys.exit("Intended for import, not execution")

