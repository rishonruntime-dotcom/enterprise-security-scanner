import pytest
from scanner.core.lifecycle import LifecycleManager
from scanner.core.exceptions import ServiceStartupError

@pytest.mark.asyncio
async def test_lifecycle_startup_shutdown():
    """Test standard startup and shutdown sequences."""
    manager = LifecycleManager()
    
    startup_called = False
    shutdown_called = False
    
    async def dummy_startup():
        nonlocal startup_called
        startup_called = True
        
    async def dummy_shutdown():
        nonlocal shutdown_called
        shutdown_called = True
        
    manager.add_startup_task(dummy_startup)
    manager.add_shutdown_task(dummy_shutdown)
    
    await manager.startup()
    assert startup_called is True
    
    await manager.shutdown()
    assert shutdown_called is True


@pytest.mark.asyncio
async def test_lifecycle_startup_failure():
    """Test that a startup failure raises ServiceStartupError."""
    manager = LifecycleManager()
    
    async def failing_startup():
        raise ValueError("simulated failure")
        
    manager.add_startup_task(failing_startup)
    
    with pytest.raises(ServiceStartupError):
        await manager.startup()
