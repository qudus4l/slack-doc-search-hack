# Slack Google Drive Search Bot

A Slack bot that allows you to search for documents across multiple users' Google Drive accounts, creating a shared searchable repository.

## Setup Instructions

1. **Install Dependencies**
   ```bash
   pip install -r requirements.txt
   ```

2. **Install and Setup ngrok**
   - Download and install ngrok from https://ngrok.com/download
   - Sign up for a free account to get your authtoken
   - Set up your authtoken:
     ```bash
     ngrok config add-authtoken your-token-here
     ```
   - Start ngrok on port 3000:
     ```bash
     ngrok http 3000
     ```
   - Keep this terminal window open while running the bot

3. **Slack Setup**
   - Create a new Slack app at https://api.slack.com/apps
   - Enable Socket Mode
   - Add the following bot token scopes:
     - `commands`
     - `chat:write`
   - Create two slash commands:
     - `/auth-drive` - For authenticating new Google Drive accounts
     - `/search-docs` - For searching documents
   - Install the app to your workspace
   - Copy the Bot User OAuth Token and App-Level Token to your `.env` file:
     ```
     SLACK_BOT_TOKEN=xoxb-your-token
     SLACK_APP_TOKEN=xapp-your-token
     ```

4. **Google Drive Setup**
   - Go to the Google Cloud Console (https://console.cloud.google.com)
   - Create a new project
   - Enable the Google Drive API
   - Go to "APIs & Services" > "Credentials"
   - Click "Create Credentials" > "OAuth 2.0 Client ID"
   - Set Application Type to "Web Application"
   - Add your ngrok HTTPS URL to "Authorized JavaScript origins"
   - Add your ngrok callback URL to "Authorized redirect URIs":
     ```
     https://[your-ngrok-url]/oauth2callback
     ```
     (You'll get this URL when you start the bot)
   - Click "Create"
   - Download the credentials and save them as `credentials.json` in the project directory

5. **Running the Bot**
   ```bash
   python app.py
   ```
   The bot will print your ngrok URLs. Make sure to:
   1. Copy the OAuth callback URL
   2. Add it to your Google OAuth credentials in the Google Cloud Console
   3. Update it whenever you restart ngrok (as the URL changes)

## Usage

1. **Authentication**
   Each user who wants to share their documents needs to authenticate once:
   ```
   /auth-drive
   ```
   The bot will send them a DM with a button to authenticate their Google Drive account.
   After clicking the button, they'll be redirected to Google's OAuth page.
   Once authentication is complete, their documents will be included in the search pool.

2. **Searching Documents**
   Search across all authenticated users' documents:
   ```
   /search-docs document-name
   ```
   For example:
   - `/search-docs monthly report`
   - `/search-docs budget 2024`

The bot will return up to 10 matching documents with their links and show which user's drive each document is from. 