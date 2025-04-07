import os
import json
import logging
from google.cloud import storage
from google.oauth2 import service_account
from datetime import datetime, timedelta
from flask import Flask, request, jsonify

class CloudStorage:
    def __init__(self):
        try:
            # Get absolute path to service account file
            service_account_path = os.path.abspath(
                os.path.join(os.path.dirname(__file__), "service-account.json")
            )
            
            # Verify file exists
            if not os.path.exists(service_account_path):
                raise FileNotFoundError(f"Service account file not found at: {service_account_path}")
                
            # Load and validate JSON
            try:
                with open(service_account_path, 'r') as f:
                    credentials_info = json.load(f)
            except json.JSONDecodeError as e:
                raise ValueError(f"Invalid JSON in service account file: {e}")
            
            # Create credentials
            credentials = service_account.Credentials.from_service_account_file(
                service_account_path,
                scopes=['https://www.googleapis.com/auth/cloud-platform']
            )

            # Initialize client with explicit project ID
            self.client = storage.Client(
                project=credentials_info['project_id'],
                credentials=credentials
            )
            
            self.bucket_name = "cbms-storage"
            
            try:
                self.bucket = self.client.get_bucket(self.bucket_name)
                logging.info(f"Connected to existing bucket: {self.bucket_name}")
            except Exception:
                logging.info(f"Creating new bucket: {self.bucket_name}")
                self.bucket = self.client.create_bucket(
                    self.bucket_name,
                    location="asia-south1"
                )
                
        except Exception as e:
            logging.error(f"Failed to initialize Cloud Storage: {str(e)}")
            raise

    def upload_file(self, file_data, storage_path, content_type):
        if not self.bucket:
            raise Exception("Storage bucket not initialized")
            
        try:
            blob = self.bucket.blob(storage_path)
            blob.upload_from_string(file_data, content_type=content_type)
            return blob.public_url
        except Exception as e:
            logging.error(f"Upload failed: {str(e)}")
            raise

    def download_file(self, storage_path):
        if not self.bucket:
            raise Exception("Storage bucket not initialized")
            
        try:
            blob = self.bucket.blob(storage_path)
            return blob.download_as_bytes()
        except Exception as e:
            logging.error(f"Download failed: {str(e)}")
            raise

    def generate_signed_url(self, storage_path, expiration=3600, response_disposition=None, content_type=None):
        """Generate a signed URL for viewing/downloading a file"""
        if not self.bucket:
            raise Exception("Storage bucket not initialized")
            
        try:
            blob = self.bucket.blob(storage_path)
            
            # Set content type if provided
            if content_type:
                blob.content_type = content_type
                
            url = blob.generate_signed_url(
                version="v4",
                expiration=timedelta(seconds=expiration),
                method="GET",
                response_type=content_type,  # Set response content type
                response_disposition=response_disposition,  # Can be None for viewing
                generation=None
            )
            
            return url
        except Exception as e:
            logging.error(f"Failed to generate signed URL: {str(e)}")
            raise

    def delete_file(self, storage_path):
        """Delete a file from cloud storage"""
        if not self.bucket:
            raise Exception("Storage bucket not initialized")
            
        try:
            blob = self.bucket.blob(storage_path)
            blob.delete()
        except Exception as e:
            logging.error(f"Failed to delete file: {str(e)}")
            raise

# Test the connection if run directly
if __name__ == "__main__":
    try:
        storage = CloudStorage()
        logging.info(f"Successfully connected to bucket: {storage.bucket_name}")
        logging.info("Available buckets:")
        for bucket in storage.client.list_buckets():
            logging.info(f"- {bucket.name}")
    except Exception as e:
        logging.error(f"Connection test failed: {str(e)}")