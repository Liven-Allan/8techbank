from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# Create limiter without app to avoid circular imports; initialize in app.py
limiter = Limiter(key_func=get_remote_address, default_limits=[])
