FROM node:20-alpine

# Instala openssl (necessário para o Prisma) e iputils (para o ping no endpoint de diagnóstico)
RUN apk add --no-cache openssl iputils bash

WORKDIR /app

COPY package.json ./
RUN npm install

COPY tsconfig.json ./
COPY prisma ./prisma/
COPY src ./src/
COPY tests ./tests/

RUN npx prisma generate && npm run build

EXPOSE 3000

CMD ["npm", "run", "docker:start"]
