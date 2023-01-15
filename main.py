from prisma import Prisma
from prisma.models import User, Post, Comment, Profile, Like
from fastapi import FastAPI, Depends, HTTPException, status, Request, File, UploadFile, Body
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.responses import JSONResponse, RedirectResponse, HTMLResponse, PlainTextResponse, StreamingResponse
from json import dumps, loads
from jose import jwt, JWTError
from hashlib import sha256

app = FastAPI()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="oauth2/token")

@app.get("/")
async def root():
    return HTMLResponse(content="<h1>Hello, world!</h1>", status_code=200)

@app.get("/oauth2/authorize")
async def create_user(user=Body(...)):
    user_dict = loads(user)
    password = sha256(user["password"].encode()).hexdigest()
    user_dict["password"] = password
    return await User.prisma().upsert(where={"email": user_dict["email"], "password": user_dict["password"]}, data={
        "create": user_dict,
        "update": user_dict
    })
    
@app.post("/oauth2/token")
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = await User.prisma().find_unique(where={"email": form_data.username})
    if user is None:
        raise HTTPException(status_code=400, detail="Incorrect username or password")
    if sha256(form_data.password.encode()).hexdigest() != user.password:
        raise HTTPException(status_code=400, detail="Incorrect username or password")
    token = jwt.encode({"sub": user.id}, "secret", algorithm="HS256")
    return {"access_token": token, "token_type": "bearer"}

@app.get("/userinfo")
async def get_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, "secret", algorithms=["HS256"])
        user = await User.prisma().find_unique(where={"id": payload["sub"]})
        return user
    except JWTError:
        raise HTTPException(status_code=400, detail="Invalid token")
    
    
@app.get("/posts")
async def get_posts(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, "secret", algorithms=["HS256"])
        user = await User.prisma().find_unique(where={"id": payload["sub"]})
        posts = await Post.prisma().find_many(where={"authorId": user.id})
        return posts
    except JWTError:
        raise HTTPException(status_code=400, detail="Invalid token")
    
@app.post("/posts")
async def create_post(post=Body(...), token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, "secret", algorithms=["HS256"])
        user = await User.prisma().find_unique(where={"id": payload["sub"]})
        post_dict = loads(post)
        post_dict["authorId"] = user.id
        return await Post.prisma().create(data=post_dict)
    except JWTError:
        raise HTTPException(status_code=400, detail="Invalid token")
    
 
