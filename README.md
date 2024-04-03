**VirusTotal-Check-Hash-File**

This script creates a SHA256 hash for a file and sends it to VirusTotal for checking. The results can be:

 - *The file is malicious*
 - *The file is not detected as malicious*
 - *VirusTotal doesn't have a report for this file hash yet*
 - *Error*


The script does not upload files to VirusTotal. Its purpose is to quickly determine if a file is malicious or not.

Usage: Run ./virustotal-check-hash-file.py and specify the file with -f followed by the file name, for example, ./virustotal-check-hash-file.py -f malware.file

**Examples:**
![Examples](https://github.com/andre-facina/VirusTotal-Check-Hash-File/blob/main/Example.png)
