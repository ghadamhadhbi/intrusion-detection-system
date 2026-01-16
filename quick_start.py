"""
Quick Start Script for IDS Data Processing
This script automates the entire Phase 2 pipeline
"""

import os
import sys
from pathlib import Path

def print_header(title):
    """Print a formatted header"""
    print("\n" + "="*70)
    print(f"  {title}")
    print("="*70 + "\n")

def check_setup():
    """Check if the project is properly set up"""
    print_header("CHECKING PROJECT SETUP")
    
    required_dirs = ['config', 'data/raw', 'data/processed', 'data/models', 'src']
    required_files = ['config/config.yaml', 'requirements.txt', 'src/data_processing.py']
    
    missing_dirs = []
    missing_files = []
    
    # Check directories
    for dir_path in required_dirs:
        if not os.path.exists(dir_path):
            missing_dirs.append(dir_path)
            print(f"✗ Missing directory: {dir_path}")
        else:
            print(f"✓ Found directory: {dir_path}")
    
    # Check files
    for file_path in required_files:
        if not os.path.exists(file_path):
            missing_files.append(file_path)
            print(f"✗ Missing file: {file_path}")
        else:
            print(f"✓ Found file: {file_path}")
    
    if missing_dirs or missing_files:
        print("\n⚠ Setup incomplete! Please create missing directories/files.")
        return False
    else:
        print("\n✓ Project setup is complete!")
        return True

def check_dataset():
    """Check if dataset is available"""
    print_header("CHECKING DATASET")
    
    raw_path = Path("data/raw")
    csv_files = list(raw_path.glob("*.csv"))
    
    if len(csv_files) == 0:
        print("✗ No CSV files found in data/raw/")
        print("\nPlease extract your dataset:")
        print("  python extract_dataset.py")
        return False
    else:
        print(f"✓ Found {len(csv_files)} CSV files:")
        total_size = 0
        for csv in csv_files:
            size_mb = csv.stat().st_size / (1024 * 1024)
            total_size += size_mb
            print(f"  - {csv.name} ({size_mb:.2f} MB)")
        print(f"\n✓ Total dataset size: {total_size:.2f} MB")
        return True

def run_processing(sample_frac=0.1, binary=False):
    """Run the data processing pipeline"""
    print_header("RUNNING DATA PROCESSING PIPELINE")
    
    try:
        from src.data_processing import DataProcessor
        
        processor = DataProcessor()
        
        print(f"Configuration:")
        print(f"  - Sample fraction: {sample_frac*100}%")
        print(f"  - Classification: {'Binary' if binary else 'Multi-class'}")
        print(f"  - Sampling method: {processor.config['preprocessing']['sampling']['method']}")
        print(f"  - Normalization: {processor.config['preprocessing']['normalization']}")
        print()
        
        # Run pipeline
        X_train, X_val, X_test, y_train, y_val, y_test = processor.process_pipeline(
            binary_classification=binary,
            sample_frac=sample_frac
        )
        
        print_header("PROCESSING COMPLETE")
        print("Data saved to: data/processed/")
        print(f"\nFinal shapes:")
        print(f"  Training:   X={X_train.shape}, y={y_train.shape}")
        print(f"  Validation: X={X_val.shape}, y={y_val.shape}")
        print(f"  Test:       X={X_test.shape}, y={y_test.shape}")
        
        return True
        
    except Exception as e:
        print(f"\n✗ Error during processing: {e}")
        import traceback
        traceback.print_exc()
        return False

def check_processed_data():
    """Check if processed data exists"""
    print_header("CHECKING PROCESSED DATA")
    
    processed_path = Path("data/processed")
    required_files = [
        'X_train.npy', 'X_val.npy', 'X_test.npy',
        'y_train.npy', 'y_val.npy', 'y_test.npy',
        'scaler.pkl', 'label_encoder.pkl', 'feature_names.pkl'
    ]
    
    all_exist = True
    for file_name in required_files:
        file_path = processed_path / file_name
        if file_path.exists():
            size_mb = file_path.stat().st_size / (1024 * 1024)
            print(f"✓ {file_name} ({size_mb:.2f} MB)")
        else:
            print(f"✗ {file_name} (missing)")
            all_exist = False
    
    if all_exist:
        print("\n✓ All processed files are ready!")
        return True
    else:
        print("\n⚠ Some files are missing. Run processing again.")
        return False

def main():
    """Main function"""
    print_header("IDS DATA PROCESSING - QUICK START")
    print("This script will guide you through Phase 2: Data Preparation")
    
    # Step 1: Check setup
    if not check_setup():
        print("\n⚠ Please complete the project setup first.")
        return
    
    # Step 2: Check dataset
    if not check_dataset():
        print("\n⚠ Please extract your dataset first:")
        print("   python extract_dataset.py")
        return
    
    # Step 3: Check if data is already processed
    if check_processed_data():
        print("\n✓ Data is already processed!")
        choice = input("\nDo you want to reprocess? (y/n): ").strip().lower()
        if choice != 'y':
            print("\nSkipping processing. You're ready for Phase 3!")
            return
    
    # Step 4: Get user preferences
    print_header("PROCESSING OPTIONS")
    
    print("Select sample size:")
    print("  1. 10% (Quick test - ~5 minutes)")
    print("  2. 50% (Medium - ~20 minutes)")
    print("  3. 100% (Full dataset - ~45+ minutes)")
    
    sample_choice = input("\nEnter choice (1-3) [default: 1]: ").strip() or "1"
    
    sample_map = {"1": 0.1, "2": 0.5, "3": 1.0}
    sample_frac = sample_map.get(sample_choice, 0.1)
    
    print("\nSelect classification type:")
    print("  1. Binary (BENIGN vs ATTACK)")
    print("  2. Multi-class (Detect specific attacks)")
    
    class_choice = input("\nEnter choice (1-2) [default: 2]: ").strip() or "2"
    binary = (class_choice == "1")
    
    # Confirm
    print("\n" + "-"*70)
    print(f"Ready to process {sample_frac*100}% of data")
    print(f"Classification: {'Binary' if binary else 'Multi-class'}")
    print("-"*70)
    
    choice = input("\nProceed? (y/n): ").strip().lower()
    if choice != 'y':
        print("\nProcessing cancelled.")
        return
    
    # Step 5: Run processing
    success = run_processing(sample_frac=sample_frac, binary=binary)
    
    if success:
        print_header("SUCCESS! PHASE 2 COMPLETE")
        print("Next steps:")
        print("  1. Review processed data in data/processed/")
        print("  2. Proceed to Phase 3: Feature Engineering")
        print("  3. Then Phase 4: Model Training")
        print("\n✓ You're ready to build your IDS models!")
    else:
        print_header("PROCESSING FAILED")
        print("Please check the error messages above and try again.")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n⚠ Processing interrupted by user.")
    except Exception as e:
        print(f"\n✗ Unexpected error: {e}")
        import traceback
        traceback.print_exc()