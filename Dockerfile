FROM node:22-alpine
WORKDIR /app
COPY package*.json ./
RUN npm ci --production
COPY index.html server.js manifest.json sw.js logo.png favicon.svg favicon-32.png apple-touch-icon.png ./
EXPOSE 8080
CMD ["node", "server.js"]
