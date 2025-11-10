# Dockerfile
FROM node:20-alpine

# рабочая папка
WORKDIR /app

# копируем package files and install deps
COPY package.json package-lock.json* ./ 
RUN npm ci --production

# копируем код
COPY . .

# порт
EXPOSE 3000

# запуск
CMD ["node", "server.js"]
