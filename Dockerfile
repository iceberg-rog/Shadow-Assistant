FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py .
COPY installer ./installer
ENV DATA_DIR=/data PORT=8088
VOLUME ["/data"]
EXPOSE 8088
CMD ["python", "app.py"]
