FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends nodejs npm && rm -rf /var/lib/apt/lists/*

RUN useradd --create-home --shell /bin/bash labuser

RUN pip install --no-cache-dir --retries 5 --timeout 60 "chainlit==2.11.0" "requests"

WORKDIR /app
COPY app.py /app/app.py
COPY .chainlit /app/.chainlit
RUN chown -R labuser:labuser /app

USER labuser
EXPOSE 8000

CMD ["chainlit", "run", "app.py", "--host", "0.0.0.0", "--port", "8000", "--headless"]
