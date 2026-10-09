# まもり帳 単体版。調査の使い捨てコンテナを起動するため docker CLI を持ち、/var/run/docker.sock をマウントして使う (compose.yml)。
FROM node:22-bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends docker.io openssh-client ca-certificates curl && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY . /app
ENV MAMORICHO_DATA=/data MAMORICHO_PORT=7700
EXPOSE 7700
VOLUME ["/data"]
ENTRYPOINT ["node", "--no-warnings=ExperimentalWarning", "standalone/cli.mjs"]
CMD ["serve"]
