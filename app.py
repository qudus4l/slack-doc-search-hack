import os
from slack_bolt import App
from slack_bolt.adapter.socket_mode import SocketModeHandler
from dotenv import load_dotenv
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
from google.auth.transport.requests import Request
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
import pickle
import json
from pathlib import Path
from flask import Flask, request, redirect
import threading
import secrets
import requests
import logging
import datetime
from openai import OpenAI
import re

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()

# Set up OpenAI
client = OpenAI(api_key=os.environ.get("OPENAI_API_KEY"))

# Allow OAuth over HTTP for local development
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

# Initialize the Flask app for OAuth handling
flask_app = Flask(__name__)
flask_app.secret_key = secrets.token_hex(16)

# Initialize the Slack app
app = App(token=os.environ.get("SLACK_BOT_TOKEN"))

# Google Drive API setup
SCOPES = [
    'https://www.googleapis.com/auth/drive.readonly',
    'https://www.googleapis.com/auth/drive.file',
    'https://www.googleapis.com/auth/drive.metadata.readonly'
]
TOKENS_DIR = Path('tokens')
TOKENS_DIR.mkdir(exist_ok=True)

# Store temporary state for OAuth flow
oauth_states = {}

# Store user mappings (email -> slack info)
USER_MAPPINGS_FILE = Path('user_mappings.json')
if not USER_MAPPINGS_FILE.exists():
    USER_MAPPINGS_FILE.write_text('{}')

def load_user_mappings():
    """Load user mappings from file"""
    return json.loads(USER_MAPPINGS_FILE.read_text())

def save_user_mappings(mappings):
    """Save user mappings to file"""
    USER_MAPPINGS_FILE.write_text(json.dumps(mappings, indent=2))

def get_slack_info_by_email(email):
    """Get Slack user info by email"""
    mappings = load_user_mappings()
    return mappings.get(email)

def save_user_mapping(email, slack_info):
    """Save mapping between Google email and Slack info"""
    mappings = load_user_mappings()
    mappings[email] = slack_info
    save_user_mappings(mappings)

def parse_natural_language_query(query):
    """Use GPT to parse natural language into structured search parameters"""
    try:
        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": """You are a helpful assistant that converts natural language queries about documents into structured search parameters.
                Extract the following information:
                - Document type (doc, spreadsheet, presentation, etc.)
                - Key terms for the filename
                - Any temporal information (year, quarter, month)
                - Any contextual keywords
                Return as JSON with these fields: search_terms, mime_type, year, quarter.
                For mime_type use: 'document' for docs, 'spreadsheet' for sheets, 'presentation' for slides, or 'any' if unspecified."""},
                {"role": "user", "content": "Find the Q1 2024 budget presentation"},
                {"role": "assistant", "content": """{"search_terms": "budget", "mime_type": "presentation", "year": "2024", "quarter": "Q1"}"""},
                {"role": "user", "content": query}
            ],
            temperature=0
        )
        
        parsed = json.loads(response.choices[0].message.content)
        logger.info(f"Parsed query: {parsed}")
        return parsed
    except Exception as e:
        logger.error(f"Error parsing query with GPT: {str(e)}")
        return None

def build_drive_query(parsed_query):
    """Build Google Drive API query from parsed parameters"""
    mime_types = {
        'document': 'application/vnd.google-apps.document',
        'spreadsheet': 'application/vnd.google-apps.spreadsheet',
        'presentation': 'application/vnd.google-apps.presentation'
    }
    
    # Start with base search terms
    search_terms = parsed_query['search_terms']
    
    # Add temporal information if available
    if parsed_query.get('year'):
        search_terms += f" {parsed_query['year']}"
    if parsed_query.get('quarter'):
        search_terms += f" {parsed_query['quarter']}"
    
    # Build query
    query = f"name contains '{search_terms}'"
    
    # Add mime type if specified
    if parsed_query.get('mime_type') and parsed_query['mime_type'] != 'any':
        mime_type = mime_types.get(parsed_query['mime_type'])
        if mime_type:
            query += f" and mimeType='{mime_type}'"
    
    return query

@app.message(re.compile(".*"))
def handle_messages(message, say, body):
    """Handle natural language messages"""
    try:
        # Ignore messages from bots
        if message.get('bot_id'):
            return
            
        text = message['text']
        
        # Get user info from the event
        user_id = body.get('user', {}).get('id')
        if not user_id:
            user_id = message.get('user')  # Fallback to message user
        
        if not user_id:
            logger.error("Could not get user ID from message")
            say("Sorry, I couldn't process your request. Please try again.")
            return
            
        # Get user info from Slack just for the name
        try:
            user_info = app.client.users_info(user=user_id)
            user_name = user_info['user'].get('real_name') or user_info['user'].get('name')
        except Exception as e:
            logger.error(f"Error getting user info: {str(e)}")
            user_name = "Unknown User"
        
        # Find user's Google email from mappings
        google_email = None
        mappings = load_user_mappings()
        for email, info in mappings.items():
            if info['user_id'] == user_id:
                google_email = email
                break
        
        if not google_email:
            say("Please authenticate with Google Drive first using `/auth-drive`")
            return
        
        # Parse the natural language query
        parsed_query = parse_natural_language_query(text)
        if not parsed_query:
            say("I had trouble understanding that query. Could you rephrase it?")
            return
            
        # Build and execute search
        query = build_drive_query(parsed_query)
        all_results = []
        services = get_all_drive_services()
        
        if not services:
            say("No authenticated Google Drive accounts found. Use `/auth-drive` to authenticate your Google Drive.")
            return
        
        for service_info in services:
            service = service_info['service']
            owner_email = service_info['user_email']
            
            try:
                results = service.files().list(
                    q=query,
                    spaces='drive',
                    fields='files(id, name, webViewLink, mimeType)',
                    pageSize=5
                ).execute()
                
                items = results.get('files', [])
                for item in items:
                    # Check access before adding to results
                    has_access = check_access(service, item['id'], google_email)
                    all_results.append({
                        'name': item['name'],
                        'link': item['webViewLink'],
                        'owner': owner_email,
                        'type': item['mimeType'],
                        'id': item['id'],
                        'has_access': has_access,
                        'service': service
                    })
            except HttpError as e:
                logger.error(f"Error searching in {owner_email}'s drive: {str(e)}")
                continue
        
        if not all_results:
            total_users = len(list(TOKENS_DIR.glob('*.pickle')))
            say(f"No documents found matching your search across {total_users} connected drives. Try a different search term.")
            return
        
        # Format results with access information
        blocks = [
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"I found these documents that might match what you're looking for (searching across {len(services)} drives):"
                }
            }
        ]
        
        for idx, item in enumerate(all_results[:10]):
            doc_type = "document" if "document" in item['type'] else "spreadsheet" if "spreadsheet" in item['type'] else "presentation"
            
            if item['has_access']:
                blocks.append({
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"• <{item['link']}|{item['name']}> ({doc_type} from {item['owner']})"
                    }
                })
            else:
                blocks.append({
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"• {item['name']} ({doc_type} from {item['owner']}) - *No access*"
                    },
                    "accessory": {
                        "type": "button",
                        "text": {
                            "type": "plain_text",
                            "text": "Request Access"
                        },
                        "style": "primary",
                        "value": json.dumps({
                            "file_id": item['id'],
                            "owner_email": item['owner'],
                            "requester_email": google_email,
                            "requester_name": user_name,
                            "doc_name": item['name']
                        }),
                        "action_id": "request_access"
                    }
                })
        
        say(blocks=blocks)
        
    except Exception as e:
        logger.error(f"Error handling message: {str(e)}")
        say("Sorry, I encountered an error processing your request.")

def get_ngrok_url():
    """Get the public HTTPS URL from ngrok"""
    try:
        response = requests.get('http://localhost:4040/api/tunnels')
        tunnels = response.json()['tunnels']
        for tunnel in tunnels:
            if tunnel['proto'] == 'https':
                return tunnel['public_url']
    except Exception as e:
        logger.error(f"Error getting ngrok URL: {str(e)}")
        return None

def get_oauth_redirect_uri():
    """Get the OAuth redirect URI, either from env or ngrok"""
    ngrok_url = get_ngrok_url()
    if ngrok_url:
        return f"{ngrok_url}/oauth2callback"
    return os.environ.get("OAUTH_REDIRECT_URI")

def get_all_drive_services():
    """Get Google Drive service instances for all authenticated users"""
    services = []
    for token_file in TOKENS_DIR.glob('*.pickle'):
        try:
            with open(token_file, 'rb') as token:
                creds = pickle.load(token)
                
            if not creds or not creds.valid:
                if creds and creds.expired and creds.refresh_token:
                    creds.refresh(Request())
                    # Save refreshed credentials
                    with open(token_file, 'wb') as token:
                        pickle.dump(creds, token)
                else:
                    continue  # Skip invalid credentials
                    
            services.append({
                'service': build('drive', 'v3', credentials=creds),
                'user_email': token_file.stem  # filename is email
            })
        except Exception as e:
            logger.error(f"Error loading credentials for {token_file}: {str(e)}")
            continue
    return services

@app.command("/auth-drive")
def authenticate_drive(ack, command, say, body):
    """Command to authenticate a new Google Drive account"""
    ack()
    try:
        redirect_uri = get_oauth_redirect_uri()
        if not redirect_uri:
            say("Error: Could not get redirect URI. Make sure ngrok is running.")
            return

        # Create OAuth flow
        flow = Flow.from_client_secrets_file(
            'credentials.json',
            scopes=SCOPES,
            redirect_uri=redirect_uri
        )
        
        # Generate authorization URL with a secure state
        state = secrets.token_urlsafe(32)
        auth_url, _ = flow.authorization_url(
            access_type='offline',
            include_granted_scopes='true',
            state=state,
            prompt='consent'  # Always show consent screen to allow multiple users
        )
        
        # Store the state and user info for verification
        oauth_states[state] = {
            'slack_user_id': body['user_id'],
            'flow': flow,
            'created_at': datetime.datetime.now()
        }
        
        # Clean up old states (older than 10 minutes)
        current_time = datetime.datetime.now()
        expired_states = [
            s for s, data in oauth_states.items()
            if (current_time - data['created_at']).total_seconds() > 600
        ]
        for s in expired_states:
            del oauth_states[s]
        
        logger.info(f"Created OAuth state: {state} for user: {body['user_id']}")
        
        # Send DM to user with auth link and instructions
        say(
            text="Click the button below to authenticate your Google Drive. Anyone in the organization can authenticate to add their documents to the searchable pool:",
            blocks=[
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": "Click the button below to authenticate your Google Drive. Once authenticated, your documents will be searchable by anyone in the workspace using `/search-docs`."
                    }
                },
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": "*Note:* Multiple people can authenticate their Google Drive accounts. Each person's documents will be included in searches."
                    }
                },
                {
                    "type": "actions",
                    "elements": [
                        {
                            "type": "button",
                            "text": {
                                "type": "plain_text",
                                "text": "Authenticate Google Drive"
                            },
                            "url": auth_url,
                            "style": "primary"
                        }
                    ]
                }
            ],
            thread_ts=body.get("event_ts", None)
        )
    except Exception as e:
        logger.error(f"Authentication setup failed: {str(e)}")
        say(f"Authentication setup failed: {str(e)}")

@flask_app.route('/oauth2callback')
def oauth2callback():
    state = request.args.get('state')
    logger.info(f"Received OAuth callback with state: {state}")
    
    if not state:
        logger.error("No state parameter provided")
        return 'Error: No state parameter provided', 400
        
    if state not in oauth_states:
        logger.error(f"Invalid state parameter: {state}")
        return 'Error: Invalid state parameter. Please try authenticating again.', 400
    
    try:
        # Get stored flow and user info
        stored_data = oauth_states[state]
        flow = stored_data['flow']
        slack_user_id = stored_data['slack_user_id']
        
        # Get Slack user info
        user_info = app.client.users_info(user=slack_user_id)
        slack_name = user_info['user'].get('real_name') or user_info['user'].get('name')
        
        # Complete the OAuth flow
        flow.fetch_token(authorization_response=request.url)
        creds = flow.credentials
        
        # Get user email from Google credentials
        service = build('drive', 'v3', credentials=creds)
        about = service.about().get(fields='user').execute()
        google_email = about['user']['emailAddress']
        
        logger.info(f"Successfully got Google email: {google_email}")
        
        # Save credentials using Google email
        token_path = TOKENS_DIR / f"{google_email}.pickle"
        with open(token_path, 'wb') as token:
            pickle.dump(creds, token)
        
        # Save user mapping (Google email -> Slack info)
        save_user_mapping(google_email, {
            'user_id': slack_user_id,
            'name': slack_name
        })
        
        logger.info(f"Successfully authenticated {google_email} and mapped to Slack user {slack_user_id}")
        
        # Clean up state
        del oauth_states[state]
        
        # Get total number of authenticated users
        total_users = len(list(TOKENS_DIR.glob('*.pickle')))
        
        # Notify user in Slack
        app.client.chat_postMessage(
            channel=slack_user_id,
            text=f"Successfully authenticated Google Drive for {google_email}! You are user #{total_users} to connect their drive. Use `/search-docs` to search across all connected drives."
        )
        
        return "Authentication successful! You can close this window and return to Slack."
    
    except Exception as e:
        logger.error(f"Authentication failed: {str(e)}")
        # Try to notify user in Slack about the error
        try:
            app.client.chat_postMessage(
                channel=slack_user_id,
                text=f"❌ Authentication failed: {str(e)}\nPlease try again or contact support if the issue persists."
            )
        except:
            pass
        return f"Authentication failed: {str(e)}", 400

@app.command("/search-docs")
def search_docs(ack, command, say):
    ack()
    query = command['text']
    
    if not query:
        say("Please provide a search term. Example: `/search-docs monthly report`")
        return
    
    # Get user info
    try:
        user_id = command['user_id']
        
        # Get user's name from Slack
        try:
            user_info = app.client.users_info(user=user_id)
            user_name = user_info['user'].get('real_name') or user_info['user'].get('name')
        except Exception as e:
            logger.error(f"Error getting user info: {str(e)}")
            user_name = "Unknown User"
        
        # Find user's Google email from mappings
        google_email = None
        mappings = load_user_mappings()
        for email, info in mappings.items():
            if info['user_id'] == user_id:
                google_email = email
                break
        
        if not google_email:
            say("Please authenticate with Google Drive first using `/auth-drive`")
            return
            
    except Exception as e:
        logger.error(f"Error getting user info: {str(e)}")
        say("Sorry, I had trouble processing your request. Please try again.")
        return
        
    all_results = []
    services = get_all_drive_services()
    
    if not services:
        say("No authenticated Google Drive accounts found. Use `/auth-drive` to authenticate your Google Drive.")
        return
    
    try:
        for service_info in services:
            service = service_info['service']
            owner_email = service_info['user_email']
            
            try:
                results = service.files().list(
                    q=query,
                    spaces='drive',
                    fields='files(id, name, webViewLink, mimeType)',
                    pageSize=5
                ).execute()
                
                items = results.get('files', [])
                for item in items:
                    # Check access before adding to results
                    has_access = check_access(service, item['id'], google_email)
                    all_results.append({
                        'name': item['name'],
                        'link': item['webViewLink'],
                        'owner': owner_email,
                        'type': item['mimeType'],
                        'id': item['id'],
                        'has_access': has_access,
                        'service': service
                    })
            except HttpError as e:
                logger.error(f"Error searching in {owner_email}'s drive: {str(e)}")
                continue
        
        if not all_results:
            total_users = len(list(TOKENS_DIR.glob('*.pickle')))
            say(f"No documents found matching your search across {total_users} connected drives. Try a different search term.")
            return
        
        # Format results with access information
        blocks = [
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"I found these documents that might match what you're looking for (searching across {len(services)} drives):"
                }
            }
        ]
        
        for idx, item in enumerate(all_results[:10]):
            doc_type = "document" if "document" in item['type'] else "spreadsheet" if "spreadsheet" in item['type'] else "presentation"
            
            if item['has_access']:
                blocks.append({
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"• <{item['link']}|{item['name']}> ({doc_type} from {item['owner']})"
                    }
                })
            else:
                blocks.append({
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"• {item['name']} ({doc_type} from {item['owner']}) - *No access*"
                    },
                    "accessory": {
                        "type": "button",
                        "text": {
                            "type": "plain_text",
                            "text": "Request Access"
                        },
                        "style": "primary",
                        "value": json.dumps({
                            "file_id": item['id'],
                            "owner_email": item['owner'],
                            "requester_email": google_email,
                            "requester_name": user_name,
                            "doc_name": item['name']
                        }),
                        "action_id": "request_access"
                    }
                })
        
        say(blocks=blocks)
    
    except Exception as e:
        logger.error(f"Error handling search: {str(e)}")
        say("Sorry, I encountered an error processing your request.")

def run_flask():
    flask_app.run(port=3000, host='0.0.0.0')

def check_access(service, file_id, user_email):
    """Check if user has access to a file"""
    try:
        # Try to get file metadata
        service.files().get(fileId=file_id, fields='owners,permissions').execute()
        return True
    except HttpError as error:
        if error.resp.status == 403:  # No access
            return False
        raise

def request_access(service, file_id, owner_email, requester_email, requester_name):
    """Request access to a document"""
    try:
        # Get owner's Slack info
        owner_slack = get_slack_info_by_email(owner_email)
        if not owner_slack:
            return False, "Couldn't contact document owner"
        
        # Send request message to owner
        app.client.chat_postMessage(
            channel=owner_slack['user_id'],
            blocks=[
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"*Access Request*\n{requester_name} ({requester_email}) is requesting access to your document."
                    }
                },
                {
                    "type": "actions",
                    "elements": [
                        {
                            "type": "button",
                            "text": {
                                "type": "plain_text",
                                "text": "Grant Access"
                            },
                            "style": "primary",
                            "value": json.dumps({
                                "requester_email": requester_email,
                                "file_id": file_id,
                                "owner_email": owner_email
                            }),
                            "action_id": "grant_access"
                        }
                    ]
                }
            ]
        )
        return True, "Access request sent to document owner"
    except Exception as e:
        logger.error(f"Error requesting access: {str(e)}")
        return False, "Error requesting access"

@app.action("request_access")
def handle_access_request(ack, body, say):
    """Handle access request button clicks"""
    ack()
    try:
        # Extract info from action
        values = json.loads(body['actions'][0]['value'])
        requester_email = values['requester_email']
        requester_name = values['requester_name']
        file_id = values['file_id']
        owner_email = values['owner_email']
        doc_name = values['doc_name']
        
        # Get owner's Slack info
        owner_slack = get_slack_info_by_email(owner_email)
        if not owner_slack:
            say("Sorry, I couldn't contact the document owner.")
            return
        
        # Send request message to owner
        app.client.chat_postMessage(
            channel=owner_slack['user_id'],
            blocks=[
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"*Access Request*\n{requester_name} ({requester_email}) is requesting access to your document:\n*{doc_name}*"
                    }
                },
                {
                    "type": "actions",
                    "elements": [
                        {
                            "type": "button",
                            "text": {
                                "type": "plain_text",
                                "text": "Grant Access"
                            },
                            "style": "primary",
                            "value": json.dumps({
                                "requester_email": requester_email,
                                "file_id": file_id,
                                "owner_email": owner_email,
                                "doc_name": doc_name
                            }),
                            "action_id": "grant_access"
                        }
                    ]
                }
            ]
        )
        
        # Update the message to show request is pending
        app.client.chat_update(
            channel=body['container']['channel_id'],
            ts=body['container']['message_ts'],
            blocks=body['message']['blocks']
        )
        
        # Send confirmation to requester
        say(f"I've sent an access request for '{doc_name}' to {owner_email}. They'll be notified and can grant you access.")
        
    except Exception as e:
        logger.error(f"Error handling access request: {str(e)}")
        say("Sorry, there was an error requesting access.")

@app.action("grant_access")
def handle_grant_access(ack, body, say):
    """Handle access grant button clicks"""
    ack()
    try:
        # Extract info from action
        values = json.loads(body['actions'][0]['value'])
        requester_email = values['requester_email']
        file_id = values['file_id']
        owner_email = values['owner_email']
        doc_name = values['doc_name']
        
        # Get owner's credentials
        token_path = TOKENS_DIR / f"{owner_email}.pickle"
        with open(token_path, 'rb') as token:
            creds = pickle.load(token)
        
        # Create Drive service
        service = build('drive', 'v3', credentials=creds)
        
        # Grant access
        service.permissions().create(
            fileId=file_id,
            body={
                'type': 'user',
                'role': 'reader',
                'emailAddress': requester_email
            }
        ).execute()
        
        # Notify requester
        requester_slack = get_slack_info_by_email(requester_email)
        if requester_slack:
            app.client.chat_postMessage(
                channel=requester_slack['user_id'],
                text=f"Access granted! You can now view '{doc_name}'"
            )
        
        # Update original message
        app.client.chat_update(
            channel=body['container']['channel_id'],
            ts=body['container']['message_ts'],
            text=f"✅ Access granted to '{doc_name}'",
            blocks=[]
        )
        
    except Exception as e:
        logger.error(f"Error granting access: {str(e)}")
        say("Sorry, there was an error granting access.")

if __name__ == "__main__":
    # Start Flask in a separate thread
    flask_thread = threading.Thread(target=run_flask)
    flask_thread.daemon = True
    flask_thread.start()
    
    # Print the ngrok URL for setup
    ngrok_url = get_ngrok_url()
    if ngrok_url:
        print(f"\nNgrok URL: {ngrok_url}")
        print(f"OAuth Callback URL: {ngrok_url}/oauth2callback")
        print("\nMake sure to add this URL to your Google OAuth credentials!")
    
    # Start the Slack bot
    handler = SocketModeHandler(app, os.environ.get("SLACK_APP_TOKEN"))
    handler.start() 