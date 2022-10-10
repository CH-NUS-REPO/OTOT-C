FROM node:16-slim
COPY package*.json .
RUN npm i
COPY config/ config/
COPY middleware/ middleware/
COPY model/ model/
COPY app.js index.js ./
EXPOSE 8000/tcp
CMD ["npm", "start"]