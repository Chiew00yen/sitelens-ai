FROM python:3.12-slim
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 PORT=8080
WORKDIR /app
COPY requirements.lock.txt ./
RUN python -m pip install --no-cache-dir --no-compile -r requirements.lock.txt \
 && useradd --system --uid 10001 --create-home sitelens \
 && mkdir /app/evidence \
 && chown 10001:10001 /app/evidence
COPY --chown=0:0 app.py phase1.py judge_access.py gunicorn.conf.py ./
COPY --chown=0:0 templates/ ./templates/
RUN chmod 0755 /app \
 && chmod 0644 /app/requirements.lock.txt /app/app.py /app/phase1.py /app/judge_access.py /app/gunicorn.conf.py \
 && find /app/templates -type d -exec chmod 0755 {} + \
 && find /app/templates -type f -exec chmod 0644 {} +
USER 10001
EXPOSE 8080
CMD ["gunicorn","--config","gunicorn.conf.py","app:app"]
