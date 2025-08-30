# Build stage
FROM node:18-alpine as build-stage

WORKDIR /app

COPY . .

RUN npm install --no-cache

RUN npm run build

# Running stage
FROM nginx:1.17-alpine as production-stage

COPY nginx.conf /etc/nginx/conf.d/default.conf

COPY --from=build-stage /app/build /usr/share/nginx/html

CMD ["nginx", "-g", "daemon off;"]