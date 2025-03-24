# Fake API Keys for Testing
API_KEY = "V1ISk1mzjAaxkdQYSgmR5vzTW9dQmy8c"                  # Random API key
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"                   # Fake AWS Access Key
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"  # Fake AWS Secret Key
GITHUB_TOKEN = "ghp_1234567890abcdefghijKLMNOPQrstuvwx"      # Fake GitHub token
GOOGLE_API_KEY = "AIzaSyD4l-aYp1X_J9tIMLJXWqNkUiNn6jP1CCkA"   # Fake Google API key
STRIPE_SECRET_KEY = "sk_test_4eC39HqLyjWDarjtT1zdp7dc"       # Fake Stripe test secret
SLACK_TOKEN = "xoxb-123456789012-098765432109-abcdefghijkl"   # Fake Slack token
JWT_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"           # Fake JWT token
BEARER_TOKEN = "Bearer abcdefghijklmnopqrstuvwxyz123456"     # Fake Bearer token

# Simulate some functionality
def connect_to_api():
    print("Connecting with API key:", API_KEY)

def aws_connect():
    print("AWS Credentials:", AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)

def github_auth():
    print("Authenticating with GitHub token:", GITHUB_TOKEN)

def stripe_payment():
    print("Stripe Secret Key:", STRIPE_SECRET_KEY)

if __name__ == "__main__":
    connect_to_api()
    aws_connect()
    github_auth()
    stripe_payment()

