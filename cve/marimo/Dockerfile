FROM python:3.12-slim

RUN useradd --create-home --shell /bin/bash labuser

RUN pip install --no-cache-dir "marimo==0.20.4"

ENV LANG=C.UTF-8
ENV LC_ALL=C.UTF-8

WORKDIR /lab
COPY notebook.py /lab/notebook.py
RUN chown -R labuser:labuser /lab

USER labuser
EXPOSE 8080

CMD ["marimo", "edit", "/lab/notebook.py", \
     "--headless", "--host", "0.0.0.0", "--port", "8080", \
     "--token-password", "labtoken"]
