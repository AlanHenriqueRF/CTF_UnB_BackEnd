import express from 'express';
import cors from 'cors';
import path from 'path';
import dotenv from 'dotenv';
import apiRouter from './routes/api';

dotenv.config();

const app = express();
const PORT = Number(process.env.PORT) || 3000;

app.use(cors());
app.use(express.json());

// Header informativo nos responses HTTP para ambientação do CTF
app.use((_req, res, next) => {
  res.setHeader('X-Powered-By', 'SIGAA-Next-API/2.1.0 (UnB-STI-Homolog)');
  next();
});

// Rotas da API REST (/api/v1/...)
app.use('/api/v1', apiRouter);

// Serve os arquivos estáticos do Front-end (desenvolvidos pela Pessoa 2 em ../frontend ou ./public)
const frontendPath = process.env.FRONTEND_DIR || path.join(__dirname, '../../frontend');
app.use(express.static(frontendPath));

// Fallback informativo caso a Pessoa 2 ainda não tenha colocado o index.html na pasta frontend
app.get('/', (_req, res) => {
  res.sendFile(path.join(frontendPath, 'index.html'), (err) => {
    if (err) {
      res.status(200).json({
        portal: 'SIGAA-Next / LabSec UnB (Servidor de Homologação)',
        message: 'Back-end API REST operacional. Aguardando acoplamento do Front-end em /frontend.',
        endpoints_principais: [
          'GET  /api/v1/status',
          'GET  /api/v1/staff',
          'GET  /api/v1/courses/search?dept=CIC',
          'GET  /api/v1/profile',
          'PUT  /api/v1/profile',
          'POST /api/v1/admin/system-check'
        ]
      });
    }
  });
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`[SIGAA-Next API] Servidor rodando em http://0.0.0.0:${PORT}`);
});
