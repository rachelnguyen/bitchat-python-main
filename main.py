from fastapi import FastAPI, BackgroundTasks
import os
import asyncio
import logging

# Local BitChat script (adapt as needed)
from bitchat import main as bitchat_main

app = FastAPI()

# Optional: Set this in Render env vars to avoid BLE attempts
DRY_RUN = os.getenv("DRY_RUN", "true").lower() == "true"

status_message = "BitChat not started yet"
log_buffer = []

@app.get("/")
def read_root():
    return {"message": "BitChat API is live 🌐", "dry_run": DRY_RUN}

@app.get("/status")
def read_status():
    return {"status": status_message, "logs": log_buffer[-10:]}

@app.post("/start")
async def start_bitchat(background_tasks: BackgroundTasks):
    global status_message
    status_message = "BitChat starting..."

    async def run_bitchat():
        global status_message
        try:
            if DRY_RUN:
                log_buffer.append("DRY_RUN mode: BitChat BLE logic skipped.")
                await asyncio.sleep(5)  # Simulate setup
                status_message = "BitChat simulated run complete ✅"
            else:
                await bitchat_main()
        except Exception as e:
            status_message = f"BitChat crashed ❌: {str(e)}"
            log_buffer.append(status_message)

    background_tasks.add_task(run_bitchat)
    return {"message": "BitChat launched in background 🚀", "dry_run": DRY_RUN}
