FROM python:3.14-slim
WORKDIR /app
COPY apps/ai-service/requirements.lock.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY apps/ai-service/main.py .
RUN useradd --uid 10001 --create-home zeroeye
USER zeroeye
EXPOSE 8000
CMD ["uvicorn","main:app","--host","0.0.0.0","--port","8000","--no-access-log"]
