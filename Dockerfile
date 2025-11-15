FROM ubuntu:20.04
RUN apt-get update && apt-get install -y python3 netcat-traditional
COPY exploit.py /exploit.py
EXPOSE 4444
CMD ["python3", "/exploit.py"]
