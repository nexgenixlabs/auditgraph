.PHONY: help backend frontend api ui dev stop clean

help:
	@echo ""
	@echo "AuditGraph - Local Dev Commands"
	@echo "--------------------------------"
	@echo "make backend   -> setup backend venv + install deps"
	@echo "make api       -> run backend API (Flask) on :5001"
	@echo "make frontend  -> install frontend deps"
	@echo "make ui        -> run frontend UI (React) on :3000"
	@echo "make dev       -> run api + ui (two terminals recommended)"
	@echo "make clean     -> remove backend venv and frontend node_modules"
	@echo ""

backend:
	cd backend && python3 -m venv venv && ./venv/bin/pip install -r requirements.txt

api:
	cd backend && ./venv/bin/python -m app.main

frontend:
	cd frontend && npm install

ui:
	cd frontend && npm run dev

dev:
	@echo "Run these in two terminals:"
	@echo "  Terminal 1: make api"
	@echo "  Terminal 2: make ui"

clean:
	rm -rf backend/venv frontend/node_modules
