FROM alpine:3.19

RUN apk add --no-cache \
    bind-tools \
    python3

COPY placeholder.py /app/placeholder.py

WORKDIR /app
CMD ["python3", "placeholder.py"]
