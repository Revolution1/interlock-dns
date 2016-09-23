FROM daocloud.io/python:2.7-slim

MAINTAINER revol.cai <crj93106@gmail.com>

COPY . /dns
WORKDIR /dns
RUN pip install --no-cache-dir -r requirements.pip

EXPOSE 53

CMD /dns/server.py