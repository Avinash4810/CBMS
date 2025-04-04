
import logging
from gcloud import CloudStorage

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

def test_storage():
    try:
        # Initialize storage
        logging.info("Initializing Cloud Storage...")
        storage = CloudStorage()

        # Create test data
        test_data = b"Hello, Cloud Storage!"
        test_path = "test/hello.txt"

        # Upload test file
        logging.info("Uploading test file...")
        public_url = storage.upload_file(
            test_data,
            test_path,
            "text/plain"
        )
        logging.info(f"File uploaded successfully. URL: {public_url}")

        # Download test file
        logging.info("Downloading test file...")
        downloaded_data = storage.download_file(test_path)
        assert downloaded_data == test_data
        logging.info("File downloaded successfully")

        # Generate signed URL
        logging.info("Generating signed URL...")
        signed_url = storage.generate_signed_url(test_path)
        logging.info(f"Signed URL generated: {signed_url}")

        return True

    except Exception as e:
        logging.error(f"Test failed: {str(e)}")
        return False

if __name__ == "__main__":
    success = test_storage()
    if success:
        print("\nStorage test completed successfully! ✅")
    else:
        print("\nStorage test failed! ❌")