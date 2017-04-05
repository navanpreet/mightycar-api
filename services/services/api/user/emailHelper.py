import base64
import httplib2
import os

from email.mime.text import MIMEText

from apiclient.discovery import build
from oauth2client.client import flow_from_clientsecrets
from oauth2client.file import Storage
from oauth2client import tools

def sendEmail(emailFrom, emailTo, emailTitle, emailBody):
	dir_path = os.path.dirname(os.path.realpath(__file__))

	# File path of the client_secret.json downloaded from the Developer Console
	CLIENT_SECRET_FILE = dir_path + '/client_id.json'

	# https://developers.google.com/gmail/api/auth/scopes will provide you with all scopes available
	OAUTH_SCOPE = 'https://www.googleapis.com/auth/gmail.compose'

	# File Location for storing the credentials
	STORAGE = Storage(dir_path + '/gmail.storage')

	# Starting OAuth flow for retrieving credentials
	flow = flow_from_clientsecrets(CLIENT_SECRET_FILE, scope=OAUTH_SCOPE)
	http = httplib2.Http()

	# Retrieving credentials from the storage location if available, else generating them
	credentials = STORAGE.get()
	if credentials is None or credentials.invalid:
		credentials = tools.run_flow(flow, STORAGE, http=http)

	# Authorizing httplib2.Http object with the credentials
	http = credentials.authorize(http)

	# Building Gmail service from discovery
	gmail_service = build('gmail', 'v1', http=http)

	# creating a message to send
	message = MIMEText(emailBody)
	message['to'] = emailTo
	message['from'] = emailFrom
	message['subject'] = emailTitle
	raw = base64.urlsafe_b64encode(message.as_bytes())
	raw = raw.decode()
	body = {'raw': raw}

	# Sending email
	try:
		message = (gmail_service.users().messages().send(userId="me", body=body).execute())
		# print('Successfully sent message Id: %s' % message['id'])
		# print(message)
		return message
	except Exception as error:
		# print('An error occurred: %s' % error)
		return {}