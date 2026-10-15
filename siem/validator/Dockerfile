# Validator image for the Ranger SIEM test runner. A Dockerfile build (not Nixpacks)
# so that Railway service variables (admin/validator credentials) are injected at
# RUNTIME only and are never baked into image build args / layers.
FROM python:3.12-slim

WORKDIR /app
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY . /app

# Credentials come from the environment at runtime, never from build args.
CMD ["python", "-m", "siem.validate_live"]
