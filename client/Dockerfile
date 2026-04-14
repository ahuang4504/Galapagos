FROM alpine:3.19

RUN apk add --no-cache \
    bind-tools \
    python3

COPY . /app/

WORKDIR /app
CMD ["python3", "placeholder.py"]
