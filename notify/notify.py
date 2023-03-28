import os
import smtplib
import socket
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from datetime import datetime
from dotenv import load_dotenv

load_dotenv('credentials.env')

class Notify:
    
    sender = os.getenv('NOTIFY_EMAIL_SENDER')
    sender_password = os.getenv('NOTIFY_PASSWORD_SENDER')
    receiver = os.getenv('NOTIFY_EMAIL_RECEIVER')

    @staticmethod
    def send_alert(attack):
        message = MIMEMultipart('alternative')
        message['Subject'] = 'Intrusion Detection Alert'
        message['From'] = Notify.sender
        message['To'] = Notify.receiver
        html = Notify.create_email_body(attack)
        content = MIMEText(html, 'html')
        message.attach(content)

        server = smtplib.SMTP('smtp-mail.outlook.com', 587)
        try:
            server.starttls();
            server.login(Notify.sender, Notify.sender_password)
            server.send_message(message, Notify.sender, Notify.receiver)
        except smtplib.SMTPException as e:
            print(f'(ERROR) Notify : {e}')
        finally:
            server.quit()

    @classmethod
    def create_email_body(cls, attack):
        now = datetime.now().strftime('%d/%m/%Y %H:%M:%S')
        hostname = socket.gethostname()
        html = Notify.get_email_template()
        return html.format(now=now, hostname=hostname, attack=attack)
    
    @classmethod
    def get_email_template(cls):
        try:
            with open('template.html', 'r', encoding='utf-8') as html_file:
                return html_file.read()
        except FileNotFoundError:
            print('(ERROR) Notify : HTML template file not found!')
            return ''
        except Exception as e:
            print(f'(ERROR) Notify : {e}')
            return ''
