# WebShellHunter
WebShell Hunter is ParaFlares contribution to the InfoSec communities ongoing efforts to find and eliminate webshells.

This tool was designed with SOC's in mind, so with that we decided whatever the tool looked like, we must be able to push it to a remote clients web server, run the scan and then retrieve the results as easily as possible. This led to a few design choices:

- No software dependencies. You aren't likely to be able to install extra software on your clients infrastructure just to run a tool.
- No extra library dependencies. We only want to push one file across to the endpoint for execution.

For this reason we have initially decided to write the tool in powershell. This is because most webservers we protect happen to be hosted on Windows (Sorry Linux heavy SOCs). The tradeoff for this decision is speed. Powershell is not the fastest language out there.

## Usage

Steps:
- Download [Hunter.ps1](https://github.com/ParaFlare/WebShellHunter/blob/master/Hunter.ps1)
- Push the script to whatever endpoint you'd like to scan
- Execute it with whatever switches you'd like (See below for switches)
- Retrieve your results JSON file or just look at the command output if you didnt select -json
- Remove the script from the endpoint

![Scan Results](https://github.com/ParaFlare/WebShellHunter/blob/master/Images/results.PNG)

## Switches

* **-HuntPath**
   The directory you would like to hunt for webshells in
* **-testPath**
   A second optional directory where you can place some actual webshell to test detections
* **-json**
  Path to output results in JSON format
* **-detailed**
 Threads will return verbose messaging as they scan files.
 This will impact performance and is meant for debugging.
* **-err**
 Turn on error messaging from threads
* **-speedInfo**
  Threads will return information on execution times.
  Use this to find and optimize performance on slow functions
* **-missedShells**
  Use this if you have -testPath selected to also output whenever a shell in your testpath is missed by every single detection method
  
## Examples

Scan C:\Inetpub\wwwroot and output the results to .\results.json
> .\Hunter.ps1 -HuntPath C:\Inetpub\wwwroot\ -json results.json

Scan from the current directory with no test path and no results file
> .\Hunter.ps1

Scan a web directory and also scan a second directory with legitimate webshell inside it. This is useful
to test whether or not a webshell would have been detected amidst the noise of your legitimate files, without having
to place a webshell in your web directory.
> .\Hunter.ps1 -HuntPath C:\Inetpub\wwwroot -testPath c:\users\webshells\testshells\ -json results.json


## TODOs

- [ ] More Detection Methods
- [ ] Rewrite in Go?
- [ ] Make str_replace work with variables
- [X] Make a ToDo list to give me an easy win
