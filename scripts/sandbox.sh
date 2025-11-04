#!/usr/bin/env bash
set -e

NAME="sandbox-$1"
IMAGE=${2:-"alpine:latest"}

if [ -z "$1" ]; then
  echo "Uso: ./sandbox.sh <nome> [imagem]"
  exit 1
fi

echo "Criando sandbox $NAME com imagem $IMAGE"
docker run -d --name "$NAME" --network none --memory 256m --cpus .5 "$IMAGE" sleep 3600
echo "Sandbox criado: $NAME"

# Para parar e remover:
# docker stop $NAME && docker rm $NAME
