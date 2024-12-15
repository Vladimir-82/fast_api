"""Greate and login user."""

from fastapi import (
    Depends,
    FastAPI,
    HTTPException,
    status,
)
from fastapi.security import (
    HTTPBasic,
    HTTPBasicCredentials,
)
from pydantic import BaseModel
from passlib.context import CryptContext  # type: ignore

app = FastAPI()
security = HTTPBasic()
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


class User(BaseModel):
    username: str
    password: str


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


def auth_user(credentials: HTTPBasicCredentials = Depends(security)):
    """Authenticate user with given credentials."""
    user = USERS.get(credentials.username)
    if user and pwd_context.verify(credentials.password, user['password']):
        return user

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail='Incorrect username or password',
        headers={'WWW-Authenticate': 'Basic'},
    )


@app.get('/login', dependencies=[Depends(auth_user)])
async def auth():
    """Login user."""
    return 'You got my secret, welcome'


@app.post("/create_user", response_model=User)
async def create_user(user: User):
    """Create new user."""
    hashed_password = pwd_context.hash("pass")
    user_data = user.model_dump()
    user_data['password'] = hashed_password
    USERS[user.username] = user_data
    return user


@app.get("/users", dependencies=[Depends(auth_user)])
async def get_users():
    """Get all users."""
    return ', '.join([user for user in USERS])


@app.get("/my_self", dependencies=[Depends(auth_user)], response_model=User)
def get_my_self(credentials: HTTPBasicCredentials = Depends(security)):
    """Get my info."""
    return auth_user(credentials)
