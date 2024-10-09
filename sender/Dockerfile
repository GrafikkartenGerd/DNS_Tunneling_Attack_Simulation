FROM python:3.9-slim
WORKDIR /app
RUN pip install scapy dnspython
COPY sender.py /app/
COPY secret_file.txt /app/
CMD ["python", "/app/sender.py"]
