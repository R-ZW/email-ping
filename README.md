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
uvicorn server:app --host 0.0.0.0 --port 8000
```

### 3️⃣ Mandar o email
```powershell
python send_email.py -server <https://url_do_servidor.com> -recipient <destinatario@email.com> -token <token_gerado>
```