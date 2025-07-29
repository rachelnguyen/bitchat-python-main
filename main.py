from fastapi import FastAPI
import asyncio
from bitchat import main as bitchat_main

app = FastAPI()

@app.get("/")
def hello():
    return {"message": "BitChat API is live!"}

@app.post("/start")
async def start_bitchat():
    # Replace this with a safer subset or mock logic for cloud
    asyncio.create_task(bitchat_main())
    return {"status": "BitChat started"}
