from flask import Flask, request, jsonify, make_response, render_template
import base64
import urllib.parse
import requests
import os
from datetime import datetime, timedelta

app = Flask(__name__)

# Replace with your actual API base URL if different
API_BASE_URL = "https://api.vrchat.cloud/api/1"

# Define the User-Agent string
USER_AGENT = "rain-1 vrchat-friend-list v2"

# Function to encode username and password for Basic Auth
def encode_auth(username, password):
    # Check if username and password are not None and convert them to strings if they are.
    if username is not None:
        username = str(username)
    if password is not None:
        password = str(password)
        
    encoded_username = urllib.parse.quote(username) if username else ""
    encoded_password = urllib.parse.quote(password) if password else ""

    combined = f"{encoded_username}:{encoded_password}"
    encoded_bytes = base64.b64encode(combined.encode('utf-8'))
    encoded_string = encoded_bytes.decode('utf-8')
    return encoded_string

# Function to handle the /auth/user endpoint
def login_auth(username, password, cookies=None):
    #only encode if username and password are provided.
    encoded_auth = ""
    if username is not None and password is not None:
        encoded_auth = encode_auth(username, password)

    headers = {
        "Authorization": f"Basic {encoded_auth}",
        "User-Agent": USER_AGENT  # Add User-Agent header here
    }
    if cookies is not None:
        headers['Cookie'] = cookies

    url = f"{API_BASE_URL}/auth/user"
    response = requests.get(url, headers=headers)
    return response

# Function to handle the /auth/twofactorauth/totp/verify endpoint
def verify_2fa(code, auth_cookie):
    headers = {
        "Content-Type": "application/json",
        "Cookie": f"auth={auth_cookie}",
        "User-Agent": USER_AGENT  # Add User-Agent header here
    }
    data = {
        "code": code
    }
    url = f"{API_BASE_URL}/auth/twofactorauth/totp/verify"
    response = requests.post(url, headers=headers, json=data)
    return response

# Function to handle the /logout endpoint
def logout_auth(auth_cookie):
    headers = {
      "Cookie": f"auth={auth_cookie}",
      "User-Agent": USER_AGENT
    }
    url = f"{API_BASE_URL}/logout"
    response = requests.put(url, headers=headers)
    return response
    

# Route for the login page
@app.route('/', methods=['GET', 'POST'])
def login():
    auth_cookie = request.cookies.get('auth')

    # Check if the auth cookie exists and is not expired
    if auth_cookie:
        response = login_auth(None, None, f"auth={auth_cookie}")  # Try to use existing auth cookie

        if response.status_code == 200:
            user_data = response.json()
            
            two_fa_cookie = None
            if 'Set-Cookie' in response.headers:
                 for cookie in response.headers['Set-Cookie'].split(','):
                    if 'twoFactorAuth=' in cookie:
                       two_fa_cookie = cookie.split(';')[0].split('=')[1]
                       break
            
            user_data['two_fa_cookie'] = two_fa_cookie
            # User is already logged in, show user info page
            response = make_response(render_template('user_info.html', user=user_data))
            
            if two_fa_cookie is not None:
                 response.set_cookie('twoFactorAuth', two_fa_cookie, httponly=True)
            return response
        
    # Handle Login
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        # First attempt: user name and password login
        response = login_auth(username, password)

        if response.status_code == 200:
            # Check if 2FA is required
            user_data = response.json()
            if 'requiresTwoFactorAuth' in user_data and 'totp' in user_data['requiresTwoFactorAuth']:
              # Handle 2fa request
                auth_cookie = None
                if 'Set-Cookie' in response.headers:
                   for cookie in response.headers['Set-Cookie'].split(','):
                        if 'auth=' in cookie:
                           auth_cookie = cookie.split(';')[0].split('=')[1]
                           break
                
                if auth_cookie is not None:

                    response = make_response(render_template('2fa.html', auth_cookie = auth_cookie))
                    response.set_cookie('auth', auth_cookie, httponly=True)
                    return response
                else:
                    return "Error missing auth cookies for 2fa"

            # Successful login, extract the user object and cookie if provided.
            auth_cookie = None
            if 'Set-Cookie' in response.headers:
                for cookie in response.headers['Set-Cookie'].split(','):
                    if 'auth=' in cookie:
                       auth_cookie = cookie.split(';')[0].split('=')[1]
                       break
            
            
            response = make_response(render_template('user_info.html', user=user_data))

            if auth_cookie is not None:
                 response.set_cookie('auth', auth_cookie, httponly=True)
            return response

        elif response.status_code == 401:
          # Handle invalid login
          return f"Login failed. Status code: {response.status_code}, Message: {response.text}"
        
        else:
            # Handle other errors
            return f"Login failed. Status code: {response.status_code}, Message: {response.text}"
    
    # Handle GET request (display login form)
    return render_template('login.html')

@app.route('/verify_2fa', methods=['POST'])
def verify():
    code = request.form.get('code')
    auth_cookie = request.cookies.get('auth')

    response = verify_2fa(code, auth_cookie)

    if response.status_code == 200:

        #pass in empty values for username and password
        response = login_auth("", "", f"auth={auth_cookie}")
        if response.status_code == 200:
            user_data = response.json()
            two_fa_cookie = None
            if 'Set-Cookie' in response.headers:
                 for cookie in response.headers['Set-Cookie'].split(','):
                    if 'twoFactorAuth=' in cookie:
                       two_fa_cookie = cookie.split(';')[0].split('=')[1]
                       break
            
            user_data['two_fa_cookie'] = two_fa_cookie

            response = make_response(render_template('user_info.html', user=user_data))
            
            if two_fa_cookie is not None:
                response.set_cookie('twoFactorAuth', two_fa_cookie, httponly=True)

            return response
        else:
             return f"2fa success but login falied. Status code: {response.status_code}, Message: {response.text}"

    elif response.status_code == 401:
         return f"2fa auth Failed. Status code: {response.status_code}, Message: {response.text}"
    else:
        return f"2fa login failed. Status code: {response.status_code}, Message: {response.text}"


@app.route('/logout')
def logout():
    auth_cookie = request.cookies.get('auth')
    if auth_cookie is not None:
        response = logout_auth(auth_cookie)

        if response.status_code == 200:
            #Successful log out.
            pass
        else:
            #handle error
            return f"logout error status code: {response.status_code}, Message: {response.text}"

    response = make_response("logged out")
    response.set_cookie('auth','',expires=0)
    response.set_cookie('twoFactorAuth','',expires=0)
    return response



if __name__ == '__main__':
    app.run(debug=True)
