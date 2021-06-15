FROM python:3

WORKDIR /usr/src/app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

RUN echo "wireshark-common wireshark-common/install-setuid boolean false" | debconf-set-selections
RUN apt-get update -y && apt-get install -y --force-yes rsync sqlite3 tcpdump tshark

COPY . .

CMD ["./docker_wrapper.sh"]
