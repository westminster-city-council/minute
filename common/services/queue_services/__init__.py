# common/services/queue_services/__init__.py
from common.services.queue_services.azure_service_bus import AzureServiceBusQueueService
from common.services.queue_services.base import QueueService
from common.services.queue_services.sqs import SQSQueueService
from common.settings import get_settings # adjust import to your settings module

# Lazy service factory
def get_queue_service(service_name: str | None = None) -> QueueService:
    if service_name is None:
        service_name = get_settings().QUEUE_SERVICE_NAME

    service_map = {
        "sqs": lambda: SQSQueueService(),
        "azure_service_bus": lambda: AzureServiceBusQueueService(),
    }

    service_factory = service_map.get(service_name)

    if not service_factory:
        raise ValueError(f"Invalid queue service name: {service_name}")

    service = service_factory()
    print(f"!!!!!! messaging service is {service_name}")
    return service