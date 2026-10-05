# Email Ping

Aplicação interna para criar tokens de rastreamento de e-mail, enviar mensagens
e consultar aberturas. Ela possui autenticação por função, sessões assinadas,
API com Bearer token, links públicos por posse e logs persistentes.


## Instalação e atualização

O projeto usa Python 3.14+ e [uv](https://docs.astral.sh/uv/).

```powershell
# Windows
uv sync --locked
Copy-Item .env.example .env
```

```bash
# Linux/macOS
uv sync --locked
cp .env.example .env
```

Para atualizar uma instalação existente, pare o processo, mantenha uma cópia de
`.env`, `tracking.db` e `attachments/`, atualize o código e sincronize as
dependências:

```bash
git pull --ff-only
uv sync --locked
```

Não apague o banco. A inicialização aplica a migração SQLite de forma
idempotente e preserva tokens, aberturas, e-mails e anexos existentes.

## Gerar credenciais com segurança

Execute os comandos no diretório do projeto. O utilitário solicita senhas sem
exibi-las no terminal.

```bash
# Hash Argon2 para BOOTSTRAP_ADMIN_PASSWORD_HASH
uv run python -m app.credentials password-hash

# Segredo da sessão
uv run python -m app.credentials session-secret

# Chave para criptografar senhas de app de remetentes pessoais
uv run python -m app.credentials smtp-credentials-key

# Valor aleatório no formato de token de API; normalmente a emissão deve ser
# feita pela tela administrativa, pois assim o valor fica vinculado ao usuário.
uv run python -m app.credentials api-token
```

Guarde os valores em um gerenciador de segredos. Não os coloque no Git, em
planilhas, em tickets ou no conteúdo de e-mails.

## Configuração do `.env`

Copie `.env.example` e preencha os valores. Este é o conjunto completo de
opções suportadas:

```env
# Remetente padrão. Usado se o dono do token não configurar um remetente pessoal.
GMAIL_USER=remetente@exemplo.gov.br
GMAIL_APP_PASSWORD=senha-de-app-do-gmail
SMTP_CREDENTIALS_KEY=chave-gerada-por-smtp-credentials-key

# URL externa usada no pixel e nos links públicos.
PUBLIC_BASE_URL=https://email-ping.exemplo.gov.br

# Armazenamento local.
DATABASE_PATH=tracking.db
ATTACHMENTS_DIR=attachments
MAX_ATTACHMENT_SIZE_BYTES=10485760

# Logs. Os valores abaixo são os padrões.
LOG_DIR=logs
LOG_LEVEL=INFO
LOG_MAX_BYTES=10485760
LOG_BACKUP_COUNT=10

# Sessão web.
SESSION_SECRET=segredo-gerado-com-32-ou-mais-caracteres
SESSION_MAX_AGE_SECONDS=28800
SESSION_COOKIE_SECURE=true

# Usado somente quando ainda não houver nenhum usuário no banco.
BOOTSTRAP_ADMIN_USERNAME=admin
BOOTSTRAP_ADMIN_PASSWORD_HASH=hash-argon2-gerado-por-password-hash
```

`SESSION_SECRET` é obrigatório e a aplicação encerra a inicialização se ele
estiver ausente ou tiver menos de 32 caracteres. Quando não há usuários no
banco, o nome e hash do administrador inicial também são obrigatórios e o hash
precisa ser Argon2 válido.

Em desenvolvimento local sem HTTPS, defina `SESSION_COOKIE_SECURE=false`.
Em produção, mantenha `true` e publique a aplicação atrás de HTTPS.

> **HTTP não protege senha, cookie de sessão nem Bearer token durante o
> transporte.** Não use HTTP em redes não confiáveis nem exponha a porta da
> aplicação diretamente à internet. Use HTTPS com um proxy reverso e um
> certificado válido.

## Inicialização local

Com `.env` configurado:

```bash
uv run uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

Abra `http://127.0.0.1:8000/login`. O modo `--reload` serve somente para
desenvolvimento. No servidor, execute sem `--reload`, preferencialmente sob
um serviço como systemd, e mantenha o Uvicorn escutando em `127.0.0.1` atrás
do proxy HTTPS.

## Logs

Por padrão, os arquivos ficam em `logs/` na raiz do projeto:

| Arquivo | Conteúdo |
| --- | --- |
| `logs/access.log` | Toda requisição HTTP: data/hora com fuso, IP, usuário quando autenticado, método, rota normalizada, status, duração, user-agent e request ID. |
| `logs/app.log` | Inicialização, encerramento, erros, exceções do Uvicorn e eventos de auditoria. |

Os mesmos registros também aparecem no terminal. Em Linux, o diretório recebe
permissão `0750` e os arquivos `0640`.

Os dois arquivos usam rotação por tamanho. Com os valores padrão, cada arquivo
ativo tem até 10 MB e são mantidas até 10 cópias anteriores (`.1` a `.10`).
Ao ultrapassar o limite, o arquivo ativo é renomeado, os backups mais antigos
são deslocados e o backup que exceder a retenção é removido. A aplicação
continua executando durante a rotação.

Consulta no Linux:

```bash
tail -f logs/access.log
tail -f logs/app.log
grep 'event=authorization_denied' logs/app.log
```

Consulta no PowerShell:

```powershell
Get-Content .\logs\access.log -Tail 100
Get-Content .\logs\app.log -Wait
```

O access log usa o padrão da rota, por exemplo `/pixel/{token}`, e não grava
query string. A aplicação não registra senha, cookie, header `Authorization`,
Bearer token, segredo de sessão, CSRF, token público completo, token de
rastreio completo, corpo de e-mail ou conteúdo de anexos. Valores com formato
de credencial em campos registráveis também são redigidos.

Os eventos de auditoria em `app.log` incluem login aceito ou recusado,
autenticação Bearer recusada, logout, alterações de usuários, emissão e
revogação de tokens de API, ações sobre tokens, envios, confirmações de leitura
e decisões de autorização. Eles incluem ator, função, IP, ação, resultado e
request ID; identificadores de tokens são armazenados como hash curto.

Se a aplicação estiver atrás de um proxy reverso, `request.client` poderá ser
o IP do próprio proxy. Configure o encaminhamento de IPs no Uvicorn somente
para endereços de proxies confiáveis; nunca aceite cabeçalhos de IP enviados
diretamente pela internet.

## Troca de credenciais

- **Senha de usuário:** o próprio usuário altera em **Minha conta**. Um
  administrador pode redefinir a senha em **Usuários > Gerenciar**. Ambas as
  ações invalidam sessões existentes do usuário.
- **Senha de administrador sem acesso à interface:** use
  `uv run python -m app.credentials reset-password <usuario>`. O comando pede a
  nova senha e invalida as sessões desse usuário.
- **Segredo da sessão:** gere outro com `session-secret`, substitua
  `SESSION_SECRET` no `.env` e reinicie a aplicação. Todas as sessões web
  atuais serão encerradas.
- **Token de API:** emita um novo token na tela **Usuários**, atualize apenas o
  consumidor autorizado e revogue o anterior. O valor completo aparece somente
  na emissão.
- **Chave SMTP pessoal:** se `SMTP_CREDENTIALS_KEY` for trocada ou perdida, as
  senhas de app pessoais salvas não poderão ser lidas; os usuários deverão
  configurá-las novamente.

## Rotas e autenticação

| Categoria | Rotas |
| --- | --- |
| Públicas | `GET /login`, `GET/HEAD /static/*`, `GET /public/tokens/{public_token}`, `GET /pixel/{token}` |
| Sessão web | `/`, `/ui/*`, `POST /logout`, `GET /docs`, `GET /redoc`, `GET /openapi.json` |
| Bearer API | `POST /tokens`, `GET /tokens`, `GET /tokens/{token}`, `POST /tokens/{token}/edit`, `POST /tokens/{token}/mark_external`, `POST /tokens/{token}/unmark_external`, `POST /tokens/{token}/public-link/{operation}`, `POST /tokens/{token}`, `POST /send_email`, `GET /opens/{token}`, `POST /confirm/{token}` |

As rotas de interface exigem sessão; páginas anônimas redirecionam para o
login. As APIs exigem `Authorization: Bearer <token>` e retornam `401` sem
uma credencial válida. `admin` e `tecnico` acessam a documentação; a
administração de usuários é exclusiva do `admin`.

Todos os formulários autenticados que alteram estado verificam CSRF. As APIs
Bearer não usam cookie de sessão e, por isso, não usam CSRF. Não há operações
destrutivas por `GET`.

`GET /pixel/{token}` é a única exceção de alteração de estado por GET: ele
registra uma abertura e retorna uma imagem 1×1. Essa exceção é necessária para
o rastreamento funcionar em clientes de e-mail, que carregam imagens somente
por GET; ela não exclui nem edita dados administrativos.

## Checklist para colocar no ar

1. Faça backup de `.env`, `tracking.db` e `attachments/`.
2. Atualize o código e rode `uv sync --locked`.
3. Revise `PUBLIC_BASE_URL`, `SESSION_SECRET`, hash do administrador inicial
   e configurações SMTP no `.env`.
4. Publique atrás de HTTPS com `SESSION_COOKIE_SECURE=true`.
5. Reinicie o serviço e confira `logs/app.log` para `application started`.
6. Faça login, emita ou valide um Bearer token e execute uma criação de token.
7. Verifique `logs/access.log` e `logs/app.log` e mantenha permissões restritas
   sobre ambos.


## Quick Start

### 1️⃣ Ativar o venv
```
# windows
(Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned) ; (& .venv\Scripts\Activate.ps1)

# macos/linux
source .venv/bin/activate
```

### 2️⃣ Subir o servidor
```
uvicorn app.main:app --host 0.0.0.0 --port 8000
```