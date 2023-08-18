FROM python:3.10-slim-buster
LABEL Maintainer="OsmanKandemir"
COPY . /opt
WORKDIR /opt
RUN /usr/local/bin/python -m pip install --upgrade pip
RUN pip --no-cache-dir install -r requirements.txt
ENTRYPOINT ["python", "analyzer.py"]


#docker build -t osmankandemir/threatanalyzer .
#docker run osmankandemir/threatanalyzer -d target-web.com