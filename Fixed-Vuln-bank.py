from http.server import BaseHTTPRequestHandler, HTTPServer
import urllib.parse
import secrets
from http import cookies

csrf_tokens = {}

# Users for the demo
users = {
    'daniel': 'password123',
    'pierce': 'SuperSecretPassword123!'
}

# accounts balances for the demo
balances = {
    'daniel': 1000,
    'pierce': 0
}

class VulnerableBankHandler(BaseHTTPRequestHandler):
    
    # Function for 
    def get_current_user(self):
        cookie_header = self.headers.get('Cookie')
        if cookie_header:
            parsed_cookies = cookies.SimpleCookie(cookie_header)
            if 'user_session' in parsed_cookies:
                return parsed_cookies['user_session'].value
        return None

    # Handle Pages
    def do_GET(self):
        user = self.get_current_user()

        if self.path == '/':
            if not user:
                self.send_response(302)
                self.send_header('Location', 'http://localhost:5000/login')
                self.end_headers()
                return 
            
            if user not in csrf_tokens:
                csrf_tokens[user] = secrets.token_hex(16)
            token = csrf_tokens[user]

            # main page logic
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()

            html = f"""
            <!DOCTYPE html>
            <html>
            <head>
                <title>Simple Bank - Dashboard</title>
                <style>
                    body {{ font-family: Arial, sans-serif; background-color: #f4f7f6; padding: 50px; }}
                    .container {{ max-width: 500px; margin: auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 4px 8px rgba(0,0,0,0.1); }}
                    .balance-box {{ background: #e8f4f8; padding: 15px; border-radius: 5px; font-size: 1.2em; margin-bottom: 20px; }}
                    .balance-box b {{ color: #27ae60; }}
                    input[type=text], input[type=number] {{ width: 100%; padding: 10px; margin: 8px 0 20px 0; border: 1px solid #ccc; border-radius: 4px; box-sizing: border-box; }}
                    input[type=submit] {{ width: 100%; background-color: #3498db; color: white; padding: 12px 20px; border: none; border-radius: 4px; cursor: pointer; }}
                </style>
            </head>
            <body>
                <div class="container">
                    <h2>Simple Bank</h2>
                    <p>Welcome, <b>{user.capitalize()}</b>!</p>
                    
                    <div class="balance-box">
                        Current Balance: <b>${balances.get(user, 0)}</b>
                    </div>
                    
                    <h3>Transfer Funds</h3>
                    <form action="/transfer" method="POST">
                        <input type ="hidden" name "csrf_token" value ="{token}">
                        <label>Recipient Username:</label>
                        <input type="text" name="to_user" required>
                        <label>Amount ($):</label>
                        <input type="number" name="amount" required>
                        <input type="submit" value="Send Money">
                    </form>
                </div>
            </body>
            </html>
            """
            self.wfile.write(html.encode("utf-8"))

        # login page logic
        elif self.path == '/login':
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
        
            html = """
            <!DOCTYPE html>
            <html>
            <head>
                <title>Login - Simple Bank</title>
                <style>
                    body { font-family: Arial, sans-serif; background-color: #f4f7f6; padding: 50px; }
                    .container { max-width: 400px; margin: auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 4px 8px rgba(0,0,0,0.1); }
                    input[type=text], input[type=password] { width: 100%; padding: 10px; margin: 8px 0 20px 0; border: 1px solid #ccc; border-radius: 4px; box-sizing: border-box; }
                    input[type=submit] { width: 100%; background-color: #2ecc71; color: white; padding: 12px; border: none; border-radius: 4px; cursor: pointer; font-weight: bold;}
                </style>
            </head>
            <body>
                <div class="container">
                    <h2> Bank Login</h2>
                    <form action="/login" method="POST">
                        <label>Username:</label>
                        <input type="text" name="username" required>
                        <label>Password:</label>
                        <input type="password" name="password" required>
                        <input type="submit" value="Log In">
                    </form>
                </div>
            </body>
            </html>
            """
            self.wfile.write(html.encode("utf-8"))
        else:
            self.send_error(404, "Page not found")

    # Post request logic and where the vulnerabiltiy for the demo
    def do_POST(self):
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length).decode('utf-8')
        form_data = urllib.parse.parse_qs(post_data)

        # login logic
        if self.path == '/login':
            username = form_data.get('username', [''])[0].lower()
            password = form_data.get('password', [''])[0]

            if username in users and users[username] == password:

                self.send_response(303)
                self.send_header('Set-Cookie', f'user_session={username}; Path=/; SameSite=Lax') # Now has SameSite Lax instead of none
                self.send_header('Location', 'http://localhost:5000/')
                self.send_header('Content-Length', '0')
                self.end_headers()
            else:
                self.send_response(401)
                self.send_header("Content-type", "text/html")
                self.end_headers()
                self.wfile.write(b"Invalid credentials. <a href='http://localhost:5000/login'> Try again</a>")

        # Process Transfer (Vulnarable Endpoint)
        elif self.path == '/transfer':
            user = self.get_current_user()

            if not user:
                self.send_response(401)
                self.end_headers()
                self.wfile.write(b"Unauthorized. Please log in first.")
                return
            
            # Mitigation using csrf_tokens
            submitted_token = form_data.get('csrf_token', [''])[0]
            expected_token = csrf_tokens.get(user)

            if not submitted_token or submitted_token != expected_token:
                self.send_response(403)
                self.send_header("Content-type", "text/html")
                self.end_headers()
                self.wfile.write(b"<h1>403 Forbidden</h1><p>CSRF Security Token Missing or Invalid.</p>")
                return

            recipent = form_data.get('to_user', [''])[0]
            try:
                amount = int(form_data.get('amount', [0])[0])
            except ValueError:
                amount = 0
            
            if balances.get(user, 0) >= amount and amount > 0:
                balances[user] -= amount
                balances[recipent] = balances.get(recipent, 0) + amount

                self.send_response(200)
                self.send_header("Content-type", "text/html")
                self.end_headers()
                success_html = f"Successfully transfered ${amount} to {recipent}. <br><a href='/'>Go back to Dashboard</a>"
                self.wfile.write(success_html.encode("utf-8"))
            else:
                self.send_response(400)
                self.end_headers()
                self.wfile.write(b"Insufficient funds.")

# run the server logic
def run(server_class=HTTPServer, handler_class=VulnerableBankHandler, port=5000):
    server_address = ('', port)
    httpd = server_class(server_address, handler_class)
    print(f"Starting Simple Bank server on port {port}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    httpd.server_close()
    print("Server shutting down")

if __name__ == '__main__':
    run()