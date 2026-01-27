FROM node:24-alpine AS dev

WORKDIR /app
COPY package*.json package-lock.json ./
RUN npm install
COPY . .
RUN npx prisma generate
RUN npm run build
EXPOSE 5002
CMD ["npm", "start"]