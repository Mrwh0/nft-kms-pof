FROM python:3.6
LABEL maintainer="mrwho@cointigo.com"
ADD . /flask
WORKDIR /flask
RUN pip install -r requirements.txt
EXPOSE 5080
ENTRYPOINT ["python3.6"]
CMD ["flask/flask_rest.py"]
