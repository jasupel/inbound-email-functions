import os
import json
import hashlib
import base64
import logging
from typing import Tuple, Dict, Any

import functions_framework
from flask import Request
from google.cloud import pubsub_v1
from cryptography.fernet import Fernet

# Configuración de Logging en Cloud Logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Configuración de Entorno
PROJECT_ID = os.environ.get("GCP_PROJECT")
TOPIC_ID = os.environ.get("PUBSUB_TOPIC_ID", "topic-inbound-emails")
# Clave simétrica Fernet (AES-128-CBC) para encriptación de PII
ENCRYPTION_SECRET = os.environ.get("ENCRYPTION_SECRET")

# Inicialización de clientes
publisher = pubsub_v1.PublisherClient()
topic_path = publisher.topic_path(PROJECT_ID, TOPIC_ID) if PROJECT_ID else None


def pseudonymize_email(email_address: str) -> str:
    """Genera un hash SHA-256 determinista a partir de la dirección de correo."""
    normalized_email = email_address.strip().lower()
    return hashlib.sha256(normalized_email.encode("utf-8")).hexdigest()


def encrypt_pii(data: str, secret_key: str) -> str:
    """Encripta texto sensible (PII) usando Fernet (AES)."""
    if not secret_key:
        raise ValueError("ENCRYPTION_SECRET no está configurado.")
    cipher = Fernet(secret_key.encode("utf-8"))
    encrypted_bytes = cipher.encrypt(data.strip().encode("utf-8"))
    return encrypted_bytes.decode("utf-8")


@functions_framework.http
def parse_and_publish_email(request: Request) -> Tuple[str, int]:
    """HTTP Cloud Function para procesar webhooks multipart/form-data de SendGrid."""
    if request.method != "POST":
        return "Method Not Allowed", 405

    try:
        # 1. Extraer campos de formulario de multipart/form-data
        # SendGrid envía el remitente en 'from', asunto en 'subject', texto en 'text'
        forwarded_from = request.form.get("from", "")
        subject = request.form.get("subject", "")
        text_body = request.form.get("text", "")
        html_body = request.form.get("html", "")
        sender_ip = request.form.get("sender_ip", "")

        if not forwarded_from:
            logger.warning("Solicitud recibida sin campo 'from'.")
            return "Bad Request: Missing 'from' field", 400

        # 2. Pseudonimización y Encriptación de PII
        user_id_hash = pseudonymize_email(forwarded_from)
        encrypted_email = encrypt_pii(forwarded_from, ENCRYPTION_SECRET)

        # 3. Mapear adjuntos (metadatos entregados por SendGrid)
        # Nota: SendGrid incluye archivos como multipart files bajo request.files
        attachments_metadata = []
        attachment_info_raw = request.form.get("attachment-info")
        if attachment_info_raw:
            try:
                attachment_info = json.loads(attachment_info_raw)
                for key, meta in attachment_info.items():
                    attachments_metadata.append({
                        "field_name": key,
                        "filename": meta.get("filename"),
                        "content_type": meta.get("type")
                    })
            except json.JSONDecodeError:
                logger.warning("No se pudo parsear 'attachment-info' JSON.")

        # 4. Construir Payload Normalizado para el Pipeline
        event_payload: Dict[str, Any] = {
            "pseudonymized_user_id": user_id_hash,
            "encrypted_forwarded_from": encrypted_email,
            "email_data": {
                "subject": subject,
                "text_body": text_body,
                "has_html": bool(html_body),
                "attachments": attachments_metadata,
                "sender_ip": sender_ip
            },
            "ingested_at": request.headers.get("Date") or None
        }

        # 5. Publicar Mensaje en Cloud Pub/Sub
        data_bytes = json.dumps(event_payload).encode("utf-8")

        # Se agregan atributos para filtrado/ruteo en Pub/Sub si se requiere
        future = publisher.publish(
            topic_path,
            data=data_bytes,
            has_attachments=str(len(attachments_metadata) > 0).lower()
        )
        message_id = future.result()

        logger.info(f"Mensaje procesado y publicado con éxito. PubSub Msg ID: {message_id}")

        # SendGrid requiere una respuesta 200 OK para confirmar la entrega del webhook
        return "OK", 200

    except Exception as e:
        logger.error(f"Error procesando el correo entrante: {str(e)}", exc_info=True)
        # Se retorna 500 para que SendGrid reintente el envío según sus políticas
        return "Internal Server Error", 500