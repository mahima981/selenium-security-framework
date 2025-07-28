from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
import time
import json
from datetime import datetime
import os

# Set up driver
driver = webdriver.Chrome()  # or webdriver.Firefox()

# Create results directory
desktop_path = "/Users/hb/Desktop/Mock"
os.makedirs(desktop_path, exist_ok=True)

# Initialize test results tracking
test_results = []

# Enhanced login function with result tracking
def test_login(username, password, expected_result, test_type="standard"):
    driver.get("https://practicetestautomation.com/practice-test-login/")
    time.sleep(2)

    # Enter username
    driver.find_element(By.ID, "username").clear()
    driver.find_element(By.ID, "username").send_keys(username)

    # Enter password
    driver.find_element(By.ID, "password").clear()
    driver.find_element(By.ID, "password").send_keys(password)

    # Submit
    driver.find_element(By.ID, "submit").click()
    time.sleep(2)

    # Capture screenshot with descriptive name
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    screenshot_name = f"{test_type}_{username.replace('/', '_').replace('<', '_').replace('>', '_')}_{timestamp}.png"
    driver.save_screenshot(f"{desktop_path}/{screenshot_name}")

    # Analyze results
    page_source = driver.page_source
    test_result = {
        "timestamp": datetime.now().isoformat(),
        "test_type": test_type,
        "username": username,
        "expected_result": expected_result,
        "screenshot": screenshot_name
    }

    if expected_result == "success":
        if "Logged In Successfully" in page_source:
            test_result["status"] = "PASS"
            test_result["vulnerability"] = False
            print(f"[PASS] {test_type} - Valid login test passed.")
        else:
            test_result["status"] = "FAIL"
            test_result["vulnerability"] = False
            print(f"[FAIL] {test_type} - Valid login test failed unexpectedly.")
    else:
        if "Your username is invalid!" in page_source or "Your password is invalid!" in page_source:
            test_result["status"] = "PASS"
            test_result["vulnerability"] = False
            print(f"[PASS] {test_type} - Invalid login correctly rejected.")
        elif "Logged In Successfully" in page_source:
            test_result["status"] = "VULNERABLE"
            test_result["vulnerability"] = True
            test_result["vulnerability_type"] = test_type
            print(f"[CRITICAL] {test_type} - SECURITY VULNERABILITY DETECTED! Malicious input bypassed authentication.")
        else:
            test_result["status"] = "UNKNOWN"
            test_result["vulnerability"] = False
            print(f"[UNKNOWN] {test_type} - Unexpected response received.")

    test_results.append(test_result)
    return test_result

# ADD THESE FUNCTIONS HERE - SQL Injection Testing
def test_sql_injection():
    print("\n=== SQL INJECTION TESTING ===")
    malicious_inputs = [
        "' OR '1'='1",
        "admin'--", 
        "' UNION SELECT * FROM users--",
        "'; DROP TABLE users;--",
        "admin' OR 1=1#"
    ]
    
    for payload in malicious_inputs:
        print(f"Testing SQL injection payload: {payload}")
        test_login(payload, "password", "fail", "sql_injection")
        time.sleep(1)  # Small delay between tests

# ADD THESE FUNCTIONS HERE - XSS Testing
def test_xss():
    print("\n=== XSS TESTING ===")
    xss_payloads = [
        "<script>alert('XSS')</script>",
        "javascript:alert('XSS')",
        "<img src=x onerror=alert('XSS')>",
        "';alert('XSS');//",
        "<svg onload=alert('XSS')>"
    ]
    
    for payload in xss_payloads:
        print(f"Testing XSS payload: {payload}")
        test_login(payload, "password", "fail", "xss")
        time.sleep(1)  # Small delay between tests

# ADD THIS FUNCTION - Brute Force Testing
def test_brute_force():
    print("\n=== BRUTE FORCE TESTING ===")
    common_passwords = ["password", "123456", "admin", "password123", "qwerty"]
    
    for pwd in common_passwords:
        print(f"Testing common password: {pwd}")
        test_login("admin", pwd, "fail", "brute_force")
        time.sleep(1)

# ADD THIS FUNCTION - Report Generation
def generate_security_report():
    print("\n=== GENERATING SECURITY REPORT ===")
    
    vulnerabilities_found = [r for r in test_results if r.get('vulnerability', False)]
    
    report = {
        "scan_timestamp": datetime.now().isoformat(),
        "total_tests": len(test_results),
        "vulnerabilities_found": len(vulnerabilities_found),
        "security_status": "FAIL" if vulnerabilities_found else "PASS",
        "test_summary": {
            "sql_injection_tests": len([r for r in test_results if r['test_type'] == 'sql_injection']),
            "xss_tests": len([r for r in test_results if r['test_type'] == 'xss']),
            "brute_force_tests": len([r for r in test_results if r['test_type'] == 'brute_force']),
            "standard_tests": len([r for r in test_results if r['test_type'] == 'standard'])
        },
        "vulnerabilities": vulnerabilities_found,
        "all_test_results": test_results
    }
    
    # Save detailed report
    report_filename = f"{desktop_path}/security_assessment_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(report_filename, 'w') as f:
        json.dump(report, f, indent=2)
    
    # Print summary
    print(f"Security Assessment Complete!")
    print(f"Total Tests: {report['total_tests']}")
    print(f"Vulnerabilities Found: {report['vulnerabilities_found']}")
    print(f"Security Status: {report['security_status']}")
    print(f"Detailed report saved to: {report_filename}")
    
    return report

# MAIN EXECUTION - Run all tests
def run_comprehensive_security_tests():
    print("Starting Comprehensive Security Testing Framework")
    print("=" * 50)
    
    # Standard authentication tests
    print("\n=== STANDARD AUTHENTICATION TESTS ===")
    test_login("student", "Password123", "success", "standard")
    test_login("student", "WrongPass", "fail", "standard")
    test_login("", "Password123", "fail", "standard")
    test_login("student", "", "fail", "standard")
    
    # Security vulnerability tests
    test_sql_injection()
    test_xss()
    test_brute_force()
    
    # Generate comprehensive report
    report = generate_security_report()
    
    # Close browser
    driver.quit()
    
    return report

# Run the tests
if __name__ == "__main__":
    run_comprehensive_security_tests()