from __future__ import print_function
from re import A

from requests.exceptions import ConnectionError
import json
import os.path
import requests
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
import base64
from email.mime.text import MIMEText
from bs4 import BeautifulSoup
import subprocess
import shlex
# If modifying these scopes, delete the file token.json.
SCOPES = ['https://www.googleapis.com/auth/gmail.modify']
#SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']

mail_server_domains=open("mail_server_domains.txt","rb").read().split()

def getInbox(service):
    count = 0
    # request a list of all the messages
    result = service.users().messages().list(maxResults= 10,labelIds= ['INBOX'],userId='me').execute()
  
    # We can also pass maxResults to get any number of emails. Like this:
    # result = service.users().messages().list(maxResults=200, userId='me').execute()
    messages = result.get('messages')
    # messages is a list of dictionaries where each dictionary contains a message id.
  
    # iterate through all the messages
    for msg in messages:
        # Get the message from its id
        txt = service.users().messages().get(userId='me', id=msg['id']).execute()
        #print(txt)
        # Use try-except to avoid any Errors
        try:
            # Get value of 'payload' from dictionary 'txt'
            payload = txt['payload']
            #print(payload)
            headers = payload['headers']
            #print(headers)
            # Look for Subject and Sender Email in the headers
            for d in headers:
                if d['name'] == 'Subject':
                    subject = d['value']
                if d['name'] == 'From':
                    sender = d['value']
                if d['name'] == 'Date':
                    date = d['value']

            # The Body of the message is in Encrypted format. So, we have to decode it.
            # Get the data and decode it with base 64 decoder.
            data = txt["snippet"]
            mail_json = {"Date":date,"Subject":subject,"From":sender,"Message":data}
            mail_json = json.dumps(mail_json,indent = 4)
            count += 1
            print(checkSpam(sender))
            if checkSpam(sender):
                with open("spam/"+str(count)+".json","w") as f:
                    f.write(mail_json)
            else:
                with open("inbox/"+str(count)+".json","w") as f:
                    f.write(mail_json)

            print("Date:",date)
            print("Subject: ", subject)
            print("From: ", sender)
            print("Message: ",data)
            print('\n')
        except:
            pass

def create_message(sender, to, subject, message_text):
  """Create a message for an email.

  Args:
    sender: Email address of the sender.
    to: Email address of the receiver.
    subject: The subject of the email message.
    message_text: The text of the email message.

  Returns:
    An object containing a base64url encoded email object.
  """

  message = MIMEText(message_text)
  message['to'] = to
  message['from'] = sender
  message['subject'] = subject
  raw = base64.urlsafe_b64encode(message.as_bytes())
  raw = raw.decode()
  return {'raw': raw}

def send_message(service, user_id, message):
  """Send an email message.

  Args:
    service: Authorized Gmail API service instance.
    user_id: User's email address. The special value "me"
    can be used to indicate the authenticated user.
    message: Message to be sent.

  Returns:
    Sent Message.
  """
  try:
    message = (service.users().messages().send(userId=user_id, body=message)
               .execute())
    print ('Message Id: %s' % message['id'])
    return message
  except HttpError as error:
    print('An error occurred: %s' % error)

def checkSpam(sender):
    print(sender)
    ind = sender.index("@")
    domain = sender[ind+1:]
    if(domain[-1]==">"):
        domain=domain[:-1]

    if domain in mail_server_domains:
        return False

    try:
        res = requests.get("http://"+domain).status_code
        if(res!=200):
            return False
        command = "nslookup -q=TXT " + domain
        
        p = subprocess.Popen(shlex.split(command), stdout=subprocess.PIPE, stderr=subprocess.PIPE
)
        out, err = p.communicate()
        if(b"spf1" in out):
            return False
        else:
            return True
    except ConnectionError as e:
        return True



def getSpam(service):
    # request a list of all the messages
    result = service.users().messages().list(maxResults= 10,labelIds= ['SPAM'],userId='me').execute()
  
        # We can also pass maxResults to get any number of emails. Like this:
    # result = service.users().messages().list(maxResults=200, userId='me').execute()
    messages = result.get('messages')
    # messages is a list of dictionaries where each dictionary contains a message id.
    if messages == None:
        print("Spam is empty")
        return
    # iterate through all the messages
    for msg in messages:
        # Get the message from its id
        txt = service.users().messages().get(userId='me', id=msg['id']).execute()
        #print(txt)
        # Use try-except to avoid any Errors
        try:

            # Get value of 'payload' from dictionary 'txt'
            payload = txt['payload']
            #print(payload)
            headers = payload['headers']
            #print(headers)
            # Look for Subject and Sender Email in the headers

            for d in headers:
                if d['name'] == 'Subject':
                    subject = d['value']
                if d['name'] == 'From':
                    sender = d['value']
                if d['name'] == 'Date':
                    date = d['value']

            # The Body of the message is in Encrypted format. So, we have to decode it.
            # Get the data and decode it with base 64 decoder.
            data = txt["snippet"]
            mail_json = {"Date":date,"Subject":subject,"From":sender,"Message":data}
            mail_json = json.dumps(mail_json,indent = 4)
            count += 1

            with open("spam/"+str(count)+".json","w") as f:
                f.write(mail_json)

            # The Body of the message is in Encrypted format. So, we have to decode it.
            # Get the data and decode it with base 64 decoder.
            data = txt["snippet"]
            print("Date:",date)
            print("Subject: ", subject)
            print("From: ", sender)
            print("Message: ",data)
            print('\n')
        except:
            pass


def main():
    """Shows basic usage of the Gmail API.
    Lists the user's Gmail labels.
    """
    creds = None
    # The file token.json stores the user's access and refresh tokens, and is
    # created automatically when the authorization flow completes for the first
    # time.
    if os.path.exists('token.json'):
        creds = Credentials.from_authorized_user_file('token.json', SCOPES)
    # If there are no (valid) credentials available, let the user log in.
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(
                'credentials.json', SCOPES)
            creds = flow.run_local_server(port=0)
        # Save the credentials for the next run
        with open('token.json', 'w') as token:
            token.write(creds.to_json())

    try:
        # Call the Gmail API
        service = build('gmail', 'v1', credentials=creds)
        results = service.users().labels().list(userId='me').execute()
        labels = results.get('labels', [])

        if not labels:
            print('No labels found.')
            return
        print('Labels:')
        for label in labels:
            print(label['name'])

    except HttpError as error:
        # TODO(developer) - Handle errors from gmail API.
        print(f'An error occurred: {error}')
    #message = create_message("organisationsf@gmail.com","sayoojbkumar@gmail.com","trial","Po naayintamone")
    #print(f"message created {message}")
    # message = message
    # print(f"message type {type(message)}")
    # send_message(service,"me",message)
    print("----------------INBOX-----------------------")
    getInbox(service)

    print("----------------SPAM-----------------------")
    getSpam(service)

    print(checkSpam("sarangdileep@google.com"))

if __name__ == '__main__':
    main()
