# email-ping

### 1️⃣ Ativar o venv
```powershell
# windows
(Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned) ; (& .venv\Scripts\Activate.ps1)

# macos/linux
source .venv/bin/activate
```

### 2️⃣ Subir o servidor
```powershell
# pwd -> .../email-ping/
uvicorn app.main:app --reload
```
