# VT-PScan
This Powershell Script is able to check the hash of any file and send it to the VirusTotal API to check. It will then inform if the file is malicious, suspicious or undetected. It's also able to send files that aren't on the VirusTotal database up to 32MB (due to API limitations).
*Being able to send bigger files, although possible, requires coding a new function to handle the use-case, and I simply won't be using that functionality, so there was no reason for me to program it. Feel free to make a pull request with the modifications if you want.*

### Dependencies
This program depends on the PSGallery Module Credential Manager, that has to be installed previously on your System.

### Usage
```
.\vt-pscan.ps1 "C:\Path\To\File.exe"
```
You may be required to check the execution policy on your machine to be able to run the script.

### Integration with Windows Explorer
This script can be integrated with Windows Explorer to scan files directly from the right-click context menu.
To do that, you have to modify your registy in the following way:
1. Create the following key `HKEY_CURRENT_USER\Software\Classes\*\shell\VT-PScan`
2. Add a new key under that one called "command"
3. Edit the (Default) property in "command" and write this `powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle hidden -File C:\Path\vt-pscan.ps1 %1`
4. In the parent key, you can modify (Default) to give it a title in the context menu.
5. In the parent key, you can create a string called "icon" with the path to an icon, which will be shown in the context menu.

### Credits
This script has partly used code from [EvotecIT/VirusTotalAnalyzer](https://github.com/EvotecIT/VirusTotalAnalyzer), to correnctly encode the file before sending it for scanning to the API.
