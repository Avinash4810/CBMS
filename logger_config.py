import logging
import os
from logging.handlers import RotatingFileHandler

def setup_logger(name, log_file='app.log', level=logging.DEBUG):
    """Configure logger with file and console handlers"""
    
    # Create logs directory if it doesn't exist
    if not os.path.exists('logs'):
        os.makedirs('logs')
        
    # Create formatter
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s'
    )
    
    # File handler
    file_handler = RotatingFileHandler(
        os.path.join('logs', log_file),
        maxBytes=10000000,  # 10MB
        backupCount=5
    )
    file_handler.setFormatter(formatter)
    
    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    
    # Get logger
    logger = logging.getLogger(name)
    logger.setLevel(level)
    
    # Add handlers if they don't exist
    if not logger.handlers:
        logger.addHandler(file_handler)
        logger.addHandler(console_handler)
    
    return logger