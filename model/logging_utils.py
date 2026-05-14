import logging
from typing import Optional


class ContextFormatter(logging.Formatter):
    """Logging formatter that tolerates missing contextual fields."""

    def format(self, record: logging.LogRecord) -> str:
        if not hasattr(record, "module_name"):
            record.module_name = record.name
        if not hasattr(record, "job_id"):
            record.job_id = "-"
        return super().format(record)


DEFAULT_LOG_FORMAT = (
    "%(asctime)s %(levelname)s [module=%(module_name)s job=%(job_id)s] %(message)s"
)


def configure_logger(
    name: str,
    *,
    level: int = logging.INFO,
    fmt: str = DEFAULT_LOG_FORMAT,
) -> logging.Logger:
    """Return a consistently configured logger instance."""
    logger = logging.getLogger(name)
    logger.setLevel(level)

    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(ContextFormatter(fmt))
        logger.addHandler(handler)

    logger.propagate = False
    return logger


def get_job_logger(
    logger_or_name: logging.Logger | str,
    *,
    module_name: str,
    job_id: Optional[str] = None,
) -> logging.LoggerAdapter:
    """Attach module and job context to a logger."""
    logger = (
        logger_or_name
        if isinstance(logger_or_name, logging.Logger)
        else configure_logger(logger_or_name)
    )
    return logging.LoggerAdapter(
        logger,
        {
            "module_name": module_name,
            "job_id": job_id or "-",
        },
    )
