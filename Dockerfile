FROM daocloud.io/python:2.7

MAINTAINER revol.cai <crj93106@gmail.com>

COPY . /dns
WORKDIR /dns
RUN pip install -r requirements.pip

EXPOSE 53

CMD /dns/server.py