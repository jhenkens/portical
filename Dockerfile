FROM python:3.11

WORKDIR /app
COPY requirements.txt .
RUN pip3 install -r requirements.txt

COPY run.py .

ENTRYPOINT ["python3", "run.py"]
CMD ["poll"]