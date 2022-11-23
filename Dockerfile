FROM python:3.10-alpine

ADD docker /opt/events-notifier
WORKDIR /opt/events-notifier

RUN pip install --no-cache-dir -r requirements.txt

CMD ["python", "-u", "./network_exporter_prom.py"]
