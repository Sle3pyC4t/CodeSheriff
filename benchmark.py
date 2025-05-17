#!/usr/bin/env python3
import os
import json
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import tempfile
import shutil

# Colors for terminal output
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def run_code_sheriff(package_path, temp_dir):
    """Run code-sheriff on a package and parse the results"""
    output_file = os.path.join(temp_dir, "result.json")
    
    try:
        start_time = time.time()
        subprocess.run(
            ["code-sheriff", "project", package_path, "-r", "-o", output_file],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        execution_time = time.time() - start_time
        
        with open(output_file, "r") as f:
            results = json.load(f)
            
        return results, execution_time
    except subprocess.CalledProcessError as e:
        print(f"{Colors.RED}Error analyzing {package_path}: {e}{Colors.ENDC}")
        print(f"stdout: {e.stdout.decode() if e.stdout else 'None'}")
        print(f"stderr: {e.stderr.decode() if e.stderr else 'None'}")
        return None, 0
    except FileNotFoundError:
        print(f"{Colors.RED}Error: code-sheriff command not found. Make sure it's installed.{Colors.ENDC}")
        exit(1)
    except Exception as e:
        print(f"{Colors.RED}Unexpected error analyzing {package_path}: {e}{Colors.ENDC}")
        return None, 0

def classify_package(results):
    """Classify a package as malicious, suspicious, or clean based on the scan results"""
    if not results:
        return "error"
    
    if results["summary"]["malicious_files"] > 0:
        return "malicious"
    elif results["summary"]["suspicious_files"] > 0:
        return "suspicious"
    else:
        return "clean"

def benchmark():
    """Run the benchmark on all packages in the testcases directory"""
    testcases_dir = Path("testcases")
    if not testcases_dir.exists() or not testcases_dir.is_dir():
        print(f"{Colors.RED}Error: testcases directory not found.{Colors.ENDC}")
        print("Make sure you've initialized the Git submodule:")
        print("  git submodule init")
        print("  git submodule update")
        return
    
    # Get all directories in testcases (each is a package)
    packages = [p for p in testcases_dir.iterdir() if p.is_dir() and not p.name.startswith('.')]
    print(f"{Colors.HEADER}Found {len(packages)} packages to analyze.{Colors.ENDC}")
    
    # Create a temporary directory for results
    with tempfile.TemporaryDirectory() as temp_dir:
        # Create a thread pool for parallel processing
        with ThreadPoolExecutor(max_workers=min(os.cpu_count(), 4)) as executor:
            # Submit all packages for processing
            future_to_package = {
                executor.submit(run_code_sheriff, str(pkg), temp_dir): pkg
                for pkg in packages
            }
            
            # Statistics
            results = {}
            total_time = 0
            errors = 0
            
            # Process results as they complete
            print(f"{Colors.HEADER}Starting analysis...{Colors.ENDC}")
            for i, future in enumerate(future_to_package, 1):
                package = future_to_package[future]
                try:
                    package_results, execution_time = future.result()
                    package_classification = classify_package(package_results)
                    
                    results[package.name] = {
                        "classification": package_classification,
                        "execution_time": execution_time,
                        "details": package_results
                    }
                    
                    total_time += execution_time
                    
                    # Print progress
                    if package_classification == "malicious":
                        status = f"{Colors.RED}MALICIOUS{Colors.ENDC}"
                    elif package_classification == "suspicious":
                        status = f"{Colors.YELLOW}SUSPICIOUS{Colors.ENDC}"
                    elif package_classification == "clean":
                        status = f"{Colors.GREEN}CLEAN{Colors.ENDC}"
                    else:
                        status = f"{Colors.RED}ERROR{Colors.ENDC}"
                        errors += 1
                    
                    print(f"[{i}/{len(packages)}] {package.name}: {status} in {execution_time:.2f}s")
                    
                except Exception as e:
                    print(f"[{i}/{len(packages)}] {Colors.RED}Error processing {package.name}: {e}{Colors.ENDC}")
                    errors += 1
            
        # Calculate and print statistics
        malicious_count = sum(1 for r in results.values() if r["classification"] == "malicious")
        suspicious_count = sum(1 for r in results.values() if r["classification"] == "suspicious")
        clean_count = sum(1 for r in results.values() if r["classification"] == "clean")
        
        print(f"\n{Colors.HEADER}{Colors.BOLD}Benchmark Results:{Colors.ENDC}")
        print(f"{Colors.BOLD}Total packages:{Colors.ENDC} {len(packages)}")
        print(f"{Colors.RED}{Colors.BOLD}Malicious packages:{Colors.ENDC} {malicious_count} ({malicious_count/len(packages)*100:.1f}%)")
        print(f"{Colors.YELLOW}{Colors.BOLD}Suspicious packages:{Colors.ENDC} {suspicious_count} ({suspicious_count/len(packages)*100:.1f}%)")
        print(f"{Colors.GREEN}{Colors.BOLD}Clean packages:{Colors.ENDC} {clean_count} ({clean_count/len(packages)*100:.1f}%)")
        if errors > 0:
            print(f"{Colors.RED}{Colors.BOLD}Errors:{Colors.ENDC} {errors}")
        print(f"{Colors.BOLD}Total analysis time:{Colors.ENDC} {total_time:.2f}s")
        print(f"{Colors.BOLD}Average time per package:{Colors.ENDC} {total_time/len(packages):.2f}s")
        
        # Save detailed results to a file
        with open("benchmark_results.json", "w") as f:
            json.dump({
                "summary": {
                    "total_packages": len(packages),
                    "malicious_packages": malicious_count,
                    "suspicious_packages": suspicious_count,
                    "clean_packages": clean_count,
                    "errors": errors,
                    "total_time": total_time,
                    "average_time_per_package": total_time/len(packages)
                },
                "package_results": results
            }, f, indent=2)
        
        print(f"\nDetailed results saved to {Colors.UNDERLINE}benchmark_results.json{Colors.ENDC}")

if __name__ == "__main__":
    benchmark() 