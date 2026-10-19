FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app
COPY 2_pipeline/requirements.txt ./pipeline-requirements.txt
COPY 3_ast_analyzer/requirements.txt ./analyzer-requirements.txt
RUN pip install --no-cache-dir -r pipeline-requirements.txt -r analyzer-requirements.txt
COPY 2_pipeline/ ./2_pipeline/
COPY 3_ast_analyzer/ ./3_ast_analyzer/
WORKDIR /app/2_pipeline
CMD ["python", "worker.py"]
