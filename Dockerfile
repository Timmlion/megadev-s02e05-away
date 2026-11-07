FROM node:22-alpine
WORKDIR /app
COPY away-agent.mjs /app/
COPY policy.json /app/policy.json
ENV AWAY_DIR=/data
EXPOSE 8931
CMD ["node", "/app/away-agent.mjs"]
