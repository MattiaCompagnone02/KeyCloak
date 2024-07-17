FROM python:3.9-slim

WORKDIR /app

COPY . /app

RUN pip install --no-cache-dir -r requirements.txt && apt-get update && apt-get install -y apache2-utils


EXPOSE 80

CMD ["python", "app.py"]