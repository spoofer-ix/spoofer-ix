#!/usr/bin/env python
# -*- coding: utf-8 -*-

import smtplib  # send mail
import socket   # get host name
import commands
import datetime
import base64

# using SendGrid's Python Library
# https://github.com/sendgrid/sendgrid-python
import os
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import (
    Mail, Attachment, FileContent, FileName,
    FileType, Disposition, ContentId)

"""
---------------------------------------MAIN----------------------------------------
Notify when some task has finished.

Dependencies:
sudo dpkg-reconfigure tzdata, set the correct timezone through terminal.
-----------------------------------------------------------------------------------
"""


def send_email(from_addr="lfmuller@inf.ufrgs.br",
               to_addr_list=["<USER>@gmail.com"],
               cc_addr_list=[""],
               subject="", message="",
               login="<USER>@gmail.com",
               password="<PWD>",
               smtpserver="smtp.gmail.com:587"):

    header = 'From: %s\n' % from_addr
    header += 'To: %s\n' % ','.join(to_addr_list)
    header += 'Cc: %s\n' % ','.join(cc_addr_list)
    header += 'Subject: %s\n\n' % subject
    message = header + message

    server = smtplib.SMTP(smtpserver)
    server.starttls()
    server.login(login, password)
    error = server.sendmail(from_addr, to_addr_list, message)

    if error:
        print("An error occurred when sending the notification email address")

    server.quit()


def send_notification_by_sendgrid(s_subject="", s_message="",):
    """
    Send notification using SendGrid services (free tier - 100 requests).
    :param s_subject:
    :param s_message:
    :return:
    """

    message = Mail(
        from_email='lfmuller@inf.ufrgs.br',
        to_emails='<USER>@gmail.com',
        subject=s_subject,
        plain_text_content=s_message)

    try:
        file_path = './out_classif.log'
        with open(file_path, 'rb') as f:
            data = f.read()
            f.close()
        encoded = base64.b64encode(data).decode()
        attachment = Attachment()
        attachment.file_content = FileContent(encoded)
        attachment.file_type = FileType('application/pdf')
        attachment.file_name = FileName('out_classif.txt')
        attachment.disposition = Disposition('attachment')
        message.attachment = attachment
    except Exception as e:
        print("Warning: file - out_classif.log - was not located to attach to the notification message.")

    try:
        sg = SendGridAPIClient(os.environ.get('SENDGRID_API_KEY'))
        response = sg.send(message)
        print(response.status_code)
        print(response.body)
        print(response.headers)
    except Exception as e:
        print("Warning: you don't seem to have (or not correctly) configured your "
              "Sendgrid API Key (for details check the readme.md at project root dir), "
              "you will not receive a notification by email.")


def send_notification_end_of_execution(s_command_line, fname_script, t_start, t_end):
    """
    Send email notification w/ the parameters used when the classification is over and ready to get the results.
    :param s_command_line:
    :return:
    """
    timestamp = datetime.datetime.now()
    str_date = "{:%B %d, %Y}".format(timestamp)
    str_mail_subject = str(socket.gethostname()) + ' -> ' + fname_script + \
                       ' finished: ' + str_date + ' ' \
                       + "---Total exec time: {} seconds".format(t_end - t_start)

    str_message_email = "".join(str(v + "\n") for v in s_command_line) \
                        + "\n OUTPUT LOG: \n" + commands.getoutput('cat *.log')

    send_notification_by_sendgrid(s_subject=str_mail_subject, s_message=str_message_email)
