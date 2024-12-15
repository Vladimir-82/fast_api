FROM python:3.10.12

WORKDIR /app

COPY pyproject.toml .

RUN pip install "poetry==1.2.0" setuptools wheel

RUN poetry config virtualenvs.create false

COPY pyproject.toml poetry.lock ./

RUN poetry install --no-root

COPY . .

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]