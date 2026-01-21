from fastapi import FastAPI

app = FastAPI(title="AuditGraph API", version="0.1.0")

@app.get("/")
def read_root():
    return {"message": "AuditGraph API is running!"}

@app.get("/health")
def health_check():
    return {"status": "healthy"}
