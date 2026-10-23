import uuid

def generate_correlation_id() -> str:
    """Generate a unique correlation ID."""
    return str(uuid.uuid4())
