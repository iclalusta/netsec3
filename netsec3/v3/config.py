"""Common configuration constants for the secure chat app."""

# Username must start with a letter and may contain letters, numbers and '_'
USERNAME_PATTERN = r"^[A-Za-z][A-Za-z0-9_]{2,15}$"

# Server configuration
CREDENTIALS_FILE = "user_credentials_ecdh_cr.json"
MAX_REQUESTS_PER_WINDOW = 20
REQUEST_WINDOW_SECONDS = 60
INTERNAL_NONCE_EXPIRY_SECONDS = 300
TIMESTAMP_WINDOW_SECONDS = 60
MAX_MSG_LENGTH = 512
# Headers used for peer to peer relay
RELAY_HEADERS = {"NS_TICKET", "NS_AUTH", "NS_FIN", "CHAT", "BCAST"}
