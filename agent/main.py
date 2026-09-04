"""
LifeShield Agent Main Application.
Starts the FastAPI application, initializes database, configures CORS middleware,
and runs the background consumer task to drain the EventBus into SQLite storage.
"""
import sys
import traceback
import asyncio
from pathlib import Path
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

sys.path.insert(0, str(Path(__file__).parent.parent))

from storage.database import init_db
from storage import repository
from agent.event_bus import event_bus
from api.routes import router


async def background_queue_worker():
    """
    Background worker that continuously consumes events from the EventBus
    and persists them to SQLite storage.
    """
    while True:
        try:
            event = await event_bus.get()
            repository.save_event(event)
            event_bus.task_done()
        except asyncio.CancelledError:
            break
        except Exception as e:
            print(f"[Error] Exception in background worker: {e}", file=sys.stderr)
            traceback.print_exc()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    FastAPI lifespan manager: initializes DB and starts/stops background worker.
    """
    init_db()
    worker_task = asyncio.create_task(background_queue_worker())
    
    yield
    
    worker_task.cancel()
    try:
        await worker_task
    except asyncio.CancelledError:
        pass


app = FastAPI(
    title="LifeShield Agent",
    description="Privacy-preserving local endpoint security agent API",
    version="1.0.0",
    lifespan=lifespan,
)

# CORS Middleware setup to allow browser extensions and localhost clients
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)

app.include_router(router)

if __name__ == "__main__":
    import uvicorn
    from configs.loader import get_config
    cfg = get_config()
    uvicorn.run("agent.main:app", host=cfg["agent"]["host"], port=cfg["agent"]["port"], reload=False)
