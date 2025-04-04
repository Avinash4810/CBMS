from gcloud import CloudStorage
from pprint import pprint

def check_storage():
    try:
        # Initialize storage
        storage = CloudStorage()
        print(f"\nConnected to bucket: {storage.bucket_name}")
        
        # List all files in bucket
        print("\nFiles in storage:")
        print("-" * 50)
        
        blobs = list(storage.bucket.list_blobs())
        
        if not blobs:
            print("No files found in storage")
            return
            
        for blob in blobs:
            print(f"\nFile: {blob.name}")
            print(f"Size: {blob.size / 1024:.2f} KB")
            print(f"Created: {blob.time_created}")
            print(f"Updated: {blob.updated}")
            print(f"URL: {blob.public_url}")
            print("-" * 50)
            
        print(f"\nTotal files: {len(blobs)}")
        
    except Exception as e:
        print(f"Error checking storage: {str(e)}")

if __name__ == "__main__":
    check_storage()