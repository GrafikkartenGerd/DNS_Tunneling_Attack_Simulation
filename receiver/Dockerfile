FROM python:3.9-slim
WORKDIR /app
RUN pip install dnspython scapy
RUN apt-get update && apt-get install -y libpcap-dev
CMD ["python", "/app/receiver.py"]
