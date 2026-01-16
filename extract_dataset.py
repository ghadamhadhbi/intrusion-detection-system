"""
Script to extract CICIDS2017 dataset from ZIP file
"""

import zipfile
import os
from pathlib import Path

def extract_dataset(zip_path: str, extract_to: str = "data/raw/"):
    """
    Extract ZIP file containing CICIDS2017 dataset
    
    Args:
        zip_path: Path to the ZIP file
        extract_to: Directory to extract files to
    """
    # Create directory if it doesn't exist
    os.makedirs(extract_to, exist_ok=True)
    
    print(f"Extracting {zip_path}...")
    print(f"Destination: {extract_to}")
    
    try:
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            # Get list of files
            file_list = zip_ref.namelist()
            print(f"\nFound {len(file_list)} files in archive:")
            
            # Show CSV files only
            csv_files = [f for f in file_list if f.endswith('.csv')]
            for f in csv_files:
                print(f"  - {f}")
            
            # Extract all files
            zip_ref.extractall(extract_to)
            print(f"\n✓ Extraction completed!")
            print(f"✓ Files extracted to: {os.path.abspath(extract_to)}")
            
            # List extracted CSV files
            extracted_csvs = list(Path(extract_to).rglob("*.csv"))
            print(f"\n✓ Found {len(extracted_csvs)} CSV files:")
            for csv in extracted_csvs:
                size_mb = csv.stat().st_size / (1024 * 1024)
                print(f"  - {csv.name} ({size_mb:.2f} MB)")
                
    except FileNotFoundError:
        print(f"✗ Error: ZIP file not found at {zip_path}")
        print("Please provide the correct path to your ZIP file.")
    except zipfile.BadZipFile:
        print(f"✗ Error: {zip_path} is not a valid ZIP file")
    except Exception as e:
        print(f"✗ Error during extraction: {e}")


if __name__ == "__main__":
    # Default ZIP path - modify this to match your file location
    zip_path = "CICIDS2017.zip"  # Change this to your ZIP file path
    
    print("="*60)
    print("CICIDS2017 Dataset Extraction")
    print("="*60)
    
    # Check if default path exists
    if not os.path.exists(zip_path):
        print(f"\nZIP file not found at: {zip_path}")
        print("\nPlease specify the correct path:")
        zip_path = input("Enter ZIP file path: ").strip()
    
    extract_dataset(zip_path)
    
    print("\n" + "="*60)
    print("Next steps:")
    print("1. Run: python src/data_processing.py")
    print("2. This will clean and prepare the data")
    print("="*60)