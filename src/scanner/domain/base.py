from pydantic import BaseModel, ConfigDict

class DomainEntity(BaseModel):
    """Base class for all domain entities.
    
    Provides standard validation and serialization using Pydantic.
    """
    model_config = ConfigDict(
        from_attributes=True,
        validate_assignment=True,
    )

class ServiceBase:
    """Base class for domain services."""
    pass
