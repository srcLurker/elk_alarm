#!/usr/bin/python

import smtplib
from email.mime.text import MIMEText

class Gmailer(object):
  def __init__(self, user, password):
    self._gmail_user = user
    self._gmail_password = password

  def SendEmail(self, to, subject, msg_body):
    msg = MIMEText(msg_body)
    msg['From'] = self._gmail_user
    msg['To'] = to

    if subject:
       msg["Subject"] = subject

    smtpserver = smtplib.SMTP('smtp.gmail.com', 587)
    smtpserver.ehlo()
    smtpserver.starttls()
    smtpserver.ehlo
    smtpserver.login(self._gmail_user, self._gmail_password)
    smtpserver.sendmail(self._gmail_user, [to], msg.as_string())
    smtpserver.quit()

# vim: set ts=2 sw=2 et sta sts smartindent:
