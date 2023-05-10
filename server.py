import base64
import hmac
import hashlib
import json

from typing import Optional

from fastapi import FastAPI, Form, Cookie
from fastapi.responses import Response

app = FastAPI()

KEY_SIGN = "88ba93478afcebaa4195ff61bd77a2fe44c480a1c7dc4dada652d72b06c2ba8c"  # terminal openssl rand -hex 32
PASSWORD_SALT = "21473c49b97969142c34046c8763c7c4d69d92aa84fbf8b53e0925c8ce60fa51"

#a = hashlib.sha256(('123456' + PASSWORD_SALT).encode()).hexdigest()
#print(a)


def sign_data(data: str) -> str:
    # Возвращает подписанные данные data
    return hmac.new(
        KEY_SIGN.encode(),
        msg=data.encode(),
        digestmod=hashlib.sha256
    ).hexdigest().upper()


def get_username_from_signed_string(username_signed: str) -> Optional[str]:
    print(username_signed)
    username_base64, sign = username_signed.split(".")
    # print(username_base64, sign)
    username = base64.b64decode(username_base64.encode()).decode()
    valid_sign = sign_data(username)
    return username if hmac.compare_digest(valid_sign, sign) else None


def verify_password(username: str, password: str) -> bool:
    password_hash = hashlib.sha256((password + PASSWORD_SALT).encode()).hexdigest().lower()
    stored_password_hash = users[username]["password"].lower()
    return password_hash == stored_password_hash


users = {
    "rim.linking@mail.ru": {
        "id": 1,
        "name": "Marcus",
        "password": "792485bfa1a197089c3a6c589b2c46d4967e22e43d3e94d57096cc0a8ca2278c",
    },
    "ms.sergey.e@mail.ru": {
        "id": 2,
        "name": "Sergey",
        "password": "b0a5cec3c4e8f3d45023f7fcc188be4e2a9bfa9e887cbb3e93560ac79cbb0acf"
    }
}


@app.get("/")  # функция запустится, когда придет get запрос на корневую папку
def index_page(username: Optional[str] = Cookie(default=None)):
    with open("/Users/rimanagi/VS CodeProjects/server/index.html", "r") as login_page:
        text_login_page = login_page.read()

    if not username:
        return Response(text_login_page, media_type="text/html")

    valid_username = get_username_from_signed_string(username)

    if not valid_username:
        response = Response(text_login_page, media_type="text/html")
        response.delete_cookie(key="username")
        return response

    try:
        _ = users[valid_username]
    except KeyError:
        response = Response(text_login_page, media_type="text/html")
        response.delete_cookie(key="username")
        return response
    return Response(f"Hello {users[valid_username]['name']}<br />"
                    f"Your id is {users[valid_username]['id']}", media_type="text/html") if username \
        else Response(text_login_page)


@app.post("/login")
def process_logging(username: str = Form(...), password: str = Form(...)):
    user = users.get(username)
    if not user or not verify_password(username, password):
        return Response(
            json.dumps({
                "success": False,
                "message": "I don't know who you are "
            }),
            media_type="application/json")

    response = Response(
        json.dumps({
        "success": True,
        "message": f"You have logged in {user['name']}"
    }), media_type="application/json")

    username_signed = base64.b64encode(username.encode()).decode() + "." + sign_data(username)
    response.set_cookie(key="username", value=username_signed)
    return response
