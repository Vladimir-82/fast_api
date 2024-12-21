"""Create and login user."""
import datetime

from fastapi import (
    Depends,
    FastAPI,
    HTTPException,
)
from fastapi.security import (
    HTTPBasic,
    HTTPBasicCredentials,
    OAuth2PasswordBearer,
)
from pydantic import BaseModel
from passlib.context import CryptContext
from typing import Optional
import jwt

from exceptions import credentials_exception

app = FastAPI()
security = HTTPBasic()
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


class User(BaseModel):
    """User model."""
    username: str
    password: str


class Token(BaseModel):
    """Token model."""
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: Optional[str] = None


USERS = {
    "user1": {
        "username": "user1",
        "password": pwd_context.hash("pass1"),
    },
    "user2": {
        "username": "user1",
        "password": pwd_context.hash("pass2"),
    }
}
SECRET_KEY = "your_secret_key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = datetime.timedelta(minutes=3)


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


def create_access_token(data: dict, expires_delta: Optional[datetime.timedelta] = None):
    """Creates a JWT access token."""
    to_encode = data.copy()
    expire = (
        datetime.datetime.utcnow()
        + expires_delta if expires_delta else datetime.datetime.utcnow()
        + datetime.timedelta(minutes=15)
    )
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def verify_password(plain_password, hashed_password):
    """Verify the password matches the given hash."""
    return pwd_context.verify(plain_password, hashed_password)


def authenticate_user(username: str, password: str):
    """Authenticate user."""
    user = USERS.get(username)
    if not user or not verify_password(password, user["password"]):
        return False
    return user


def create_jwt_token(data: dict):
    """Creates JWT token."""
    data.update({"exp": datetime.datetime.utcnow() + ACCESS_TOKEN_EXPIRE_MINUTES})
    return jwt.encode(data, SECRET_KEY, algorithm=ALGORITHM)


async def base_auth_user(credentials: HTTPBasicCredentials = Depends(security)):
    """Authenticate user with given credentials."""
    user = USERS.get(credentials.username)
    if user and pwd_context.verify(credentials.password, user['password']):
        return user


async def token_auth_user(token: str = Depends(oauth2_scheme)):
    """Authenticate user with given credentials."""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        token_data = TokenData(username=username)
        user = USERS.get(token_data.username)
        if user:
            return user
    except jwt.PyJWTError:
        raise credentials_exception


@app.get('/login', dependencies=[Depends(base_auth_user) or Depends(token_auth_user)])
async def auth():
    """Login user."""
    return 'You got my secret, welcome'


@app.post("/token", response_model=Token)
async def login_for_access_token(user: User):
    """Login to user using JWT."""
    if authenticate_user(user.username, user.password):
        return {"access_token": create_jwt_token({"sub": user.username}), "token_type": "bearer"}
    raise HTTPException(status_code=401, detail="Invalid credentials")


@app.post("/create_user", response_model=User)
async def create_user(user: User):
    """Create new user."""
    hashed_password = pwd_context.hash("pass")
    user_data = user.model_dump()
    user_data['password'] = hashed_password
    USERS[user.username] = user_data
    return user


@app.get("/users", dependencies=[Depends(base_auth_user) or Depends(token_auth_user)])
async def get_users():
    """Get all users."""
    return ', '.join([user for user in USERS])


@app.get("/my_self", dependencies=[Depends(base_auth_user) or Depends(token_auth_user)], response_model=User)
def get_my_self(credentials: HTTPBasicCredentials = Depends(security)):
    """Get my info."""
    if credentials:
        return {'username': credentials.username, 'password': credentials.password}
    elif token_auth_user:
        return token_auth_user
    raise credentials_exception
