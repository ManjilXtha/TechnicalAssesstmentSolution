# Technical Assesstment All The Descriptions

# Problem 1 :

## Project Description
LogMonitor is a Python-based tool that scans system logs for suspicious activity, including:
- Failed login attempts
- Unauthorized access
- Malicious activity detection

It generates alerts when such patterns are found and displays the timestamp if available.

## Steps to Run The Code

1. Ensure you have Python installed on your system.  
2. Place your log file (`system_logs.txt`) in the folder:  
    C:\technical assesstment
3. Save the script as `log_monitor.py`.  
4. Open your terminal or command prompt.  
5. Run the script using:  
    python log_monitor.py
6. When prompted, enter the path to the log file:  
 
    Enter the path to the log file: C:\technical assesstment\system_logs.txt
  

## Assumptions and Limitations

- Checks for these patterns (case insensitive):  
  - "failed login"  
  - "unauthorized access"  
  - "malicious activity detected"  
- Supports common timestamp formats like:  
  - `2024-12-22 10:45:00`
  - `22/Dec/2024:10:45:00`
- If no timestamp is found, the current time is used.  
- Alerts are printed to the console but can be modified to log to a file.  
- This version is a basic parser and does not support advanced threat detection.


# Problem 2:


## Project Description
WebScanCrawler is a Python-based web crawler that scans websites for common security vulnerabilities. It checks for:
- Missing HTTP security headers.
- Outdated software versions.
- Forms that lack security attributes.

## Steps to Run The Code

1. Ensure you have Python installed on your system.
2. Clone the repository:
   git clone https://github.com/ManjilXtha/WebScanCrawler.git
3. Install dependencies : pip install requests beautifulsoup4
4. Run The Code or Script : python WebScanCrawler.py

## Assumptions and Limitations

- The crawler currently checks for a limited set of vulnerabilities (security headers, outdated 
  software versions, and insecure forms).
- The scan is performed on a single domain. Links from other domains are not crawled.
- The script does not handle CAPTCHA or other bot protection mechanisms on websites.
- The software version detection is based on patterns found in the Server header and the page - 
  content, which may not always be accurate.
- The program may take time to crawl large websites with many pages.


