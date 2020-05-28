# WebShellHunter
WebShell Hunter is ParaFlares contribution to the InfoSec communities ongoing efforts to find and eliminate webshells.

This tool was designed with SOC's in mind, so with that we decided whatever the tool looked like, we must be able to push it to a remote clients web server, run the scan and then retrieve the results as easily as possible. This led to a few design choices:

- No software dependencies. You aren't likely to be able to install extra software on your clients infrastructure just to run a tool.
- No extra library dependencies. We only want to push one file across to the endpoint for execution.

For this reason we have initially decided to write the tool in powershell. This is because most webservers we protect happen to be hosted on Windows (Sorry Linux heavy SOCs). The tradeoff for this decision is speed. Powershell is not the fastest language out there.

##Usage

Steps:
- Download ![Hunter.ps1](https://github.com/ParaFlare/WebShellHunter/blob/master/Hunter.ps1)
- Push the script to whatever endpoint you'd like to scan
- Execute it with whatever switches you'd like (See below for switches)
- Retrieve your results JSON file or just look at the command output if you didnt select -json
- Remove the script from the endpoint


![Scan Results](https://github.com/ParaFlare/WebShellHunter/blob/master/Images/results.PNG)
