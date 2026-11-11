import { app } from './app';

const PORT = Number(process.env.PORT) || 3000;

app.listen(PORT, '0.0.0.0', () => {
  console.log(`[SIGAA-Next API] Servidor rodando em http://0.0.0.0:${PORT}`);
});
