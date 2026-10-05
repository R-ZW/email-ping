module.exports = {
  apps: [
    {
      name: 'email-ping',
      cwd: '/home/pablo/email-ping/email-ping',

      // Uvicorn instalado no ambiente virtual do projeto.
      script: '/home/pablo/email-ping/email-ping/.venv/bin/uvicorn',
      interpreter: 'none',
      args: 'app.main:app --host 0.0.0.0 --port 8000',

      // Uma única instância é adequada para o SQLite atual.
      instances: 1,
      exec_mode: 'fork',

      // Reinicia somente este serviço caso ele encerre inesperadamente.
      autorestart: true,
      restart_delay: 3000,
      max_restarts: 10,

      // Acrescenta horário aos logs administrados pelo PM2.
      time: true
    }
  ]
};