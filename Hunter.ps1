<#
.SYNOPSIS
  Hunt for webshells inside a web server directory

.DESCRIPTION
  Hunt for webshells inside a web server directory. This module supports multiple filetypes

.PARAMETER HuntPath
   The directory you would like to hunt for webshells in

.PARAMETER testPath
   A second optional directory where you can place some actual webshell to test detections

.PARAMETER json
  Path to output results in JSON format

.PARAMETER detailed
 Threads will return verbose messaging as they scan files.
 This will impact performance and is meant for debugging.

.PARAMETER error
 Turn on error messaging from threads

.PARAMETER speedInfo 
  Threads will return information on execution times.
  Use this to find and optimize performance on slow functions

.PARAMETER missedShells
   if this is selected along with -testPath, we output to the screen any shells that the script didnt pick up
   as webshells at all. Use for testing new detections

.PARAMETER maxThreads
   Set the Maximum number of threads to use. Default is half of the available threads on the system.

.OUTPUTS
  Log file stored in current executing directory by default.
  Change output path with -logPath parameter. 
  Results are output in JSON format.

.NOTES
  Version:        1.0
  Author:         Aaron Williams
  Creation Date:  15 April 2020
  Purpose/Change: Initial script development
  
.EXAMPLE
  # Hunt for webshells recursively from the current directory down. Dont output results to log file. No test Path
  Hunter.ps1 

.EXAMPLE
  # Hunt for webshells in c:\inetpub\wwwroot and also scan a directory of known webshells in c:\tests. Log results to results.json
  Hunter.ps1 -huntPath c:\inetpub\wwwroot -testPath c:\tests -json results.json
#>
[CmdletBinding()]
param (
   [Parameter(Mandatory=$false)] [string]$huntPath = "./", 
   [Parameter(Mandatory=$false)] [string]$testPath,
   [Parameter(Mandatory=$false)] [string]$json,
   [Parameter(Mandatory=$false)] [switch]$detailed,
   [Parameter(Mandatory=$false)] [switch]$err,
   [Parameter(Mandatory=$false)] [switch]$speedInfo,
   [Parameter(Mandatory=$false)] [switch]$missedShells,
   [Parameter(Mandatory=$false)] [int]$maxThreads = [int]$env:NUMBER_OF_PROCESSORS /2,
   [Parameter(Mandatory=$false)] [switch]$testing
)

#---------------------------------------------------------[Initialisations]--------------------------------------------------------

#Set Error Action to Silently Continue
if ($err) {
    $ErrorActionPreference = "Continue"
}
# Flip it to "continue" if you're having troubles and want more info.
# This will DRAMATICALLY slow down script execution though
if ($detailed) {
    write-host "Enabling detailed output."
    $VerbosePreference = "Continue"
}
if ($speedInfo) {
    $InformationPreference = "Continue"
}
if ($missedShells) {
    $DebugPreference = "Continue"
}
$progressPreference = "Continue"

#----------------------------------------------------------[Declarations]----------------------------------------------------------

# performance counter
$stopwatch = New-object System.Diagnostics.Stopwatch

# The default filetypes we will scan. If none are specified.
$filetypes = @(

    "*.php",
    #"*.jsp",
    #"*.jspx",
    #"*.js",
    #"*.asp",
    #"*.aspx",
    #"*.cgi",
    #"*.pl",
    #"*.cfm",
    #"*.war",
    #"*.rb",
    "*.py"
)

$scriptblock = {
    param (
        $file,
        $detailed,
        $speedInfo,
        $missedShells,
        $testFile
    )
    
    #-----------------------------------------------------------[Debug Switches]------------------------------------------------------------
    # We have to set the preference variables again inside our scriptblock as runspace threads do not inherit any of these
    # settings from the caller
    # Turn this on with -SpeedInfo on the commandline
   if ($speedinfo) {
      $InformationPreference = "Continue" 
   }
   if ($detailed) {
       $VerbosePreference = "Continue"
   }
   if ($missedShells) {
       $DebugPreference = "Continue"
   }
    #-----------------------------------------------------------[Variables]------------------------------------------------------------

    
    # Configuration for how many strings matches (or more) in a file before we call it a webshell.
    $stringThreshold = 4
    # Any entropy score over this number will be considered a webshell
    $entThresholdUpper = 5.7
    # Any entropy score under this number will be considered a webshell
    $entThresholdLower = 2.5
    # How many characters in a single line before we declare webshell
    $lineCountThreshold = 2000
    # How many times a variable can be added to with .= before we declare webshell
    $varUsageThreshold = 50
    # List of strings to match against for our basic string match detections
   $lowConfidenceRegex = (
      '[^\d\w](exec|system|shell_exec|fsockopen|socket_create|socket_bind|WScript.Shell|assert|shell|xp_execresultset|xp_regenumkeys|xp_cmdshell|xp_filelist)',
      '[^\d\w\W](BufferedInputStream|ByteArrayOutputStream|new BASE64Decoder|.decodeBuffer|ini_set\(allow_url_fopen true\)|ini_set\(allow_url_include true\)|VBSCRIPT|Scripting.FileSystemObject|adodb.stream|system\(\$_GET|exploit|lave|noitcnuf_etaerc|metsys|urhtssap|llehs|etucexe_llehs|tressa|edoced_46esab|sserpmocnuzg|nepop|nepokcosf|tcartxe|posix_|win32_create_service|xmlrpc_decode|LD_PRELOAD)',
      '[^\d\w](eval|passthru|base64_decode|popen|proc_open|pcntl_exec|gzinflate|gzuncompress|Runtime.getRuntime\(\).exec|getenv|is_dir|getcwd|getServerInfo|System.getProperty|create_function|posix_mkfifo|posix_setsid|posix_setuid|java.lang.Runtime|chr|ord|eval\(base64_decode|goto|extract|upload|str_rot13|strrev|gzdecode|urldecode|replace_callback|register_shutdown_function|register_tick_function|safe_mode bypass)[\( "]', 
      # - https://github.com/nsacyber/Mitigating-Web-Shells/blob/master/extended.webshell_detection.yara
      "urldecode[\t ]*\([\t ]*'(%[0-9a-fA-F][0-9a-fA-F])+'[\t ]*\)",
      # "Var as Func" - https://github.com/nsacyber/Mitigating-Web-Shells/blob/master/extended.webshell_detection.yara
      '\$_(GET|POST|COOKIE|REQUEST|SERVER)\s*\[[^\]]+\]\s*\(', 
         #  concatenation of more than 5 words - https://github.com/nsacyber/Mitigating-Web-Shells/blob/master/extended.webshell_detection.yara
      '(\$[^\n\r]+\. ){5}',
      # concatenation of more than eight `chr()` - https://github.com/nsacyber/Mitigating-Web-Shells/blob/master/extended.webshell_detection.yara
      '(chr\([\d]+\)\.){8}', 
      # "variable_Variable" - https://github.com/nsacyber/Mitigating-Web-Shells/blob/master/extended.webshell_detection.yara
      '\${\$[0-9a-zA-z]+}', 
         # https://github.com/UltimateHackers/nano - https://github.com/nsacyber/Mitigating-Web-Shells/blob/master/extended.webshell_detection.yara
      'base64_decode[^;]+getallheaders',
      # https://github.com/UltimateHackers/nano - https://github.com/nsacyber/Mitigating-Web-Shells/blob/master/extended.webshell_detection.yara
      '\$[a-z0-9-_]+\[[^]]+\]\(', 
         # http://bartblaze.blogspot.fr/2015/03/c99shell-not-dead.html - https://github.com/nsacyber/Mitigating-Web-Shells/blob/master/extended.webshell_detection.yara
      ';\$\w+\(\$\w+(,\s?\$\w+)+\);',
      # Weevely3 Launcher - https://github.com/nsacyber/Mitigating-Web-Shells/blob/master/extended.webshell_detection.yara
      '\$\w=\$[a-zA-Z]\('',\$\w\);\$\w\(\);', 
         # B374k - https://github.com/nsacyber/Mitigating-Web-Shells/blob/master/extended.webshell_detection.yara
      '(\$\w+=[^;]*)*;\$\w+=@?\$\w+\('         

   )
   $highConfidenceRegex = (
      '[^\d\w\W](gcc |chmod +x|/bin/sh|/bin/bash|VBscript.Encode|cmd|.bash_history|.ssh/authorized_keys|/etc/passwd|/etc/shadow|WinExec|id_rsa)',
      # - https://github.com/nsacyber/Mitigating-Web-Shells/blob/master/extended.webshell_detection.yara
      '(\\x47\\x4c\\x4f\\x42\\x41\\x4c\\x53|\\x65\\x76\\x61\\x6C\\x28|\\x65\\x78\\x65\\x63|\\x73\\x79\\x73\\x74\\x65\\x6d|\\x70\\x72\\x65\\x67\\x5f\\x72\\x65\\x70\\x6c\\x61\\x63\\x65|\\x48\\124\\x54\\120\\x5f\\125\\x53\\105\\x52\\137\\x41\\107\\x45\\116\\x54|\\x61\\x73\\x65\\x36\\x34\\x5f\\x64\\x65\\x63\\x6f\\x64\\x65\\x28\\x67\\x7a\\x69\\x6e\\x66\\x6c\\x61\\x74\\x65\\x28)',
      # - https://github.com/nsacyber/Mitigating-Web-Shells/blob/master/extended.webshell_detection.yara
      '(474c4f42414c53|6576616C28|65786563|73797374656d|707265675f7265706c616365|61736536345f6465636f646528677a696e666c61746528)',
      # - https://github.com/nsacyber/Mitigating-Web-Shells/blob/master/extended.webshell_detection.yara
      '(SFRUUF9VU0VSX0FHRU5UCg|ZXZhbCg|c3lzdGVt|cHJlZ19yZXBsYWNl|ZXhlYyg|YmFzZTY0X2RlY29kZ|IyEvdXNyL2Jpbi9wZXJsCg|Y21kLmV4ZQ|cG93ZXJzaGVsbC5leGU)',
      # md5 password protection  - https://github.com/nsacyber/Mitigating-Web-Shells/blob/master/extended.webshell_detection.yara
      'md5\s*\(\s*\$_(GET|REQUEST|POST|COOKIE|SERVER)[^)]+\)\s*===?\s*["][0-9a-f]{32}["]',
      # sha1 password protection - https://github.com/nsacyber/Mitigating-Web-Shells/blob/master/extended.webshell_detection.yara
      'sha1\s*\(\s*\$_(GET|REQUEST|POST|COOKIE|SERVER)[^)]+\)\s*===?\s*["][0-9a-f]{40}["]'
   )
   
   # ----------- Thread Execution --------------- #
   # These two lines are the only 'execution' lines, the rest of the thread scriptblock is just
   # Detection method functions for the Check-File function to call.
   $scanResults = Search-Shells $file
   if ($scanresults.count -gt 0 ) 
   {
      [void]$fileResults.tryAdd( $file.name, [pscustomobject]@{
         # $file actually contains all of the file metadata that powershell pulls when you gci a file. We dont trim it.
         # Not sure if we should. 
         filename          = $file.Name
         filepath          = $file.Fullname
         filelength        = $file.Length
         scanResults       = $scanResults
         IsTestFile        = $testFile
      })
   }
}
Function Get-Entropy{
   Param($string)

   Begin{
        Write-Verbose "ENTROPY: Getting Entropy`n" 
        $stopwatch = New-object System.Diagnostics.Stopwatch
        $stopwatch.Start()
   }

   Process{
      Try{
         # This function is taken from https://rosettacode.org/wiki/Entropy
         # Ask me how it works are your own peril. The result is an entropy score.
         $n = $string.Length
         $entropy = $string.ToCharArray() | Group-Object | ForEach-Object {
            $p = $_.Count/$n
            $i = [Math]::Log($p,2)
            -$p*$i
         } | Measure-Object -Sum | ForEach-Object Sum

         return $entropy
      }
  
      Catch{
         Write-Error "ENTROPY: $_.Exception "
         Break
      }
   }

   End{
      If($?){
        Write-Verbose "ENTROPY: Entropy score of $entropy`n"
        $timeTaken = $stopwatch.Elapsed.TotalSeconds
        Write-Information "ENTROPY TIME:`t`tfunction executed in $timeTaken Seconds`n"
      }
   }
}

Function Find-BadStrings{
   Param($file)

   Begin{
      Write-Verbose "STRINGMATCH: Checking for badstrings`n"
      $stopwatch = New-object System.Diagnostics.Stopwatch
      $stopwatch.Start()
   }

   Process{
      Try{
         # We want to count how many blacklisted strings are in our file and return it so that we can
         # later check against $stringThreshold and determine if we are calling it a webshell
         # based on how many string matches occured. 
         $reader =  New-Object System.IO.StreamReader("$file")

         # Intiate separate arrays for low and high confidence matches. Required to due to difference in score weighting. High confidence matches being scored higher then low confidence.
         $lcStringsMatched = [System.Collections.ArrayList]@()
         $hcStringsMatched = [System.Collections.ArrayList]@()
         $linecount = 0
         # Score weighting. High confidence hits will be x by the below, in this case 5. 1 becomes 5.
         $scoreWeighting = 5
         while ($null -ne ($line = $reader.Readline())) 
         {
            $linecount++
            if ($linecount -eq 10000) 
            {
                 $lcStringsMatched = $lcStringsMatched | Select-Object -Unique
                 $hcStringsMatched = $hcStringsMatched | Select-Object -Unique
                 $stringCount = ($hcStringsMatched.Count * $scoreWeighting) + $lcStringsMatched.Count
                 $stringsmatched = $lcStringsMatched + $hcStringsMatched
                 return $stringCount, $stringsMatched
           }
            if ($Line.length -eq 0 -or $Line -match "^ *[\*/]") 
            {
                continue
            }
            foreach ($condition in $lowConfidenceRegex) 
            {
                if ($line -match $condition) 
                { 
                    $null = $lcStringsMatched.Add($Matches.0)
                    
                }
            }
            foreach ($condition in $highConfidenceRegex) 
            {
                if ($line -match $condition) 
                { 
                    $null = $hcStringsMatched.Add($Matches.0)
                    
                }
            }

         }
         $reader.Dispose()
         $lcStringsMatched = $lcStringsMatched | Select-Object -Unique
         $hcStringsMatched = $hcStringsMatched | Select-Object -Unique
         $stringCount = ($hcStringsMatched.Count * $scoreWeighting) + $lcStringsMatched.Count
         $stringsmatched = $lcStringsMatched + $hcStringsMatched
         return $stringCount, $stringsMatched
      }
  
      Catch{
         Write-Error "BADSTRING: $_.Exception "
         Break
      }
   }

   End{
      If($?){
        Write-Verbose "STRINGMATCH: found $stringCount string matches`n"
        $timeTaken = $stopwatch.Elapsed.TotalSeconds
        Write-Information "BADSTRINGS TIME:`tfunction executed in $timeTaken Seconds`n"
      }
   }
}

Function Find-StrReplaceObfuscation{
   Param($fileContents)

   Begin{
    Write-Verbose "STRREPLACE: Checking for String Replace Sneakiness`n"
    $stopwatch = New-object System.Diagnostics.Stopwatch
    $stopwatch.Start()
   }

   Process{
      Try{
         $stringsMatched = [System.Collections.ArrayList]@()
         
         # This will pull an array of every line containing a str_replace and all of its associated garbage
         # we'll trim it down to size next.
         $keys = $filecontents -split '\n' | Select-String "str_replace"
         # we have to loop over every str_replace because its common to have a few different obfuscations that need to be undone
         foreach ($key in $keys) {
            # Gotta string each line so we can do our string operations like indexOf.
            # its not a string initially but a [Microsoft.PowerShell.Commands.MatchInfo] 
            $key = $key.ToString()
            # Replace any double quotes with single quotes, so we dont have to deal with the possibility
            # of double OR single quotes in our keys for the rest of our operations. Sounds trivial but
            # saves a ton of headaches.
            $key = $key.replace('"', "'")
            $key = $key.replace(" ", "")
            # backslashes were ruining my day, Idk how to escape them within variables for the .split function ahead.
            # So if we are finding something with a backslash, just dont even bother.
            if ($key -match "str_replace.'',''.") {
               $key = $key.replace("str_replace(''","str_replace(' '")
               continue
            }
            # Find where str_replace is in the line so we can cut out the rest of the lines garbage
            # that we dont care about
            $i =  $key.IndexOf("str_replace")
            # this effectively cuts out all of the start of the string up until the first key e.g.
            # $B=str_replace('xJ','','cxJrexJxJatxJe_fuxJnctixJon');
            #  gets trimmed to
            # 'xJ','','cxJrexJxJatxJe_fuxJnctixJon');
            # now we are sitting at our decoding key
            $key = $key.substring($i+12)
            # using the example above, splitting by , and grabbing the 0th index gives us 'xJ' which is our decoding 
            if ($key -match "('[\w]*,[\w]+')|('[\w]+,[\w]*')") {
               # write-host "skipping key: $key"
               continue
            }
            $src = $key.Split((','))[0]
            # and grabbing the 1st index gives us '' which is what to replace it with. It's usually an empty string but attackers can be
            # weird, so put in the ability to replace the key with whatever the attacker chooses.
            $dst = $key.Split((','))[1]
            # Strip out the ' characters so we can match properly.
            # e.g. "xJ" becomes xJ. Without this we just wouldnt match anything and the obfuscation remains.
            $src = $src -replace "'",""
            $dst = $dst -replace "'",""      
            # String the filecontents so we can do a .replace annnddd
            $fileContents = $fileContents.ToString()
            # DECODE
            
            Write-Verbose "REPLACE: src:$src dst:$dst`n"
            $filecontents = $filecontents.Replace($src, $dst)
         }
         
         $fileContents -split '\n' | ForEach-Object {
            $line = $_
            if ($Line -match "^ *[\*/]") 
            {
                continue
            }
             write-verbose "CHECKING: $line`n"
             foreach ($condition in $regexList) 
                {
                    $hit = ($line | select-string $condition -AllMatches).Matches.Value
                    if ($hit) 
                    { 
                        $hit | ForEach-Object {                                          
                            Write-Verbose "Found Matches: $_`n"
                            $null = $stringsMatched.Add($_)
                        }
                    
                    }
                }
        }
        $stringsMatched = $stringsMatched | Select-Object -Unique
        $stringCount = $stringsMatched.Count
         # The deobfuscated contents arent checked for webshell stuff here, simply passed back to Check-File to be put through all the usual tests.
         return $stringsMatched, $stringCount
      }
      Catch{
         Write-Error "STRREPLACE: $_.Exception "
         Break
      }
   }

   End{
      If($?){
        $count = $keys.count
        Write-Verbose "STRREPLACE: found and replaced $count str_replace keys.`n"
        $timeTaken = $stopwatch.Elapsed.TotalSeconds
        Write-Information "STRREPLACE TIME:`tfunction executed in $timeTaken Seconds`n"
      }
   }
}

Function Get-LongestLineCount{
   Param($file)

   Begin{
      Write-Verbose "LONGESTLINE: Finding Longest Line Length`n"
      $stopwatch = New-object System.Diagnostics.Stopwatch
      $stopwatch.Start()
   }

   Process{
      Try{
             $reader =  New-Object System.IO.StreamReader("$file")
        [int]$lineLen = 0
        [string]$longestLine = "" 
        while ($null -ne ($line = $reader.ReadLine())) {
            if ($line.Contains("svg")) { continue}
            if ($line.Contains("data:image")) { continue }
            if ($line.Length -gt $lineLen) {
                $longestLine = $line
                $lineLen = $line.Length
            }
        }
        $reader.Dispose()
         
        return $lineLen, $longestLine               

      }
  
      Catch{
         Write-Error "LONGLINE: $_.Exception "
         Break
      }
   }

   End{
      If($?){
        Write-Verbose "LONGESTLINE: Longest Line Length is $LineLen characters`n"
        $timeTaken = $stopwatch.Elapsed.TotalSeconds
        Write-Information "LONGLINE TIME:`t`tfunction executed in $timeTaken Seconds`n"
      }
   }
}

Function Get-VariableUsageCount{
   Param($file)

   Begin{
      Write-Verbose "OVERLYUSEDVARIABLE: Find Variable with the most additions`n"
      $stopwatch = New-object System.Diagnostics.Stopwatch
      $stopwatch.Start()
   }

   Process{
      Try{
         $reader =  New-Object System.IO.StreamReader("$file")

        $varsCount = @{}
        while ($null -ne ($line = $reader.ReadLine()))
        {
    
   
            if ($line -match ('(\$[\d\w]+ +\.=)'))
            {
              $val = $Matches.0
                if ($VarsCount.Containskey($val)) 
                {
                    $VarsCount[$val]++
                    
                } 
                else 
                {
                    $VarsCount[$val] = 1
                }
            }
        }
        $MostAddedtoVarCount = ($VarsCount.GetEnumerator() | Sort-Object -property Value -Descending | Select-Object -first 1).value
        $MostAddedtoVar = ($VarsCount.GetEnumerator() | Sort-Object -property Value -Descending | Select-Object -first 1).Name
        $reader.Dispose()
        return $MostAddedtoVarCount, $MostAddedtoVar
        $reader.Dispose()

      }
  
      Catch{
         Write-Error "VARUSAGE:" $_.Exception 
         Break
      }
   }

   End{
      If($?){
        Write-Verbose "OVERLYUSEDVARIABLE: The most used variable has additions made $mostAddedToVarCount times.`n"
        $timeTaken = $stopwatch.Elapsed.TotalSeconds
        Write-Information "VARUSAGE TIME:`t`tfunction executed in $timeTaken Seconds`n"
      }
   }
}

Function Search-Shells
{
   Param($file)

   Begin
   {
      Write-Verbose "FILECHECK: Checking file $file`n"
      Write-Information "TIMING FILE $file`n"
      $stopwatch = New-object System.Diagnostics.Stopwatch
      $stopwatch.Start()
   }
   Process
   {
      Try
      {
         # Each file will have its scan results stored in a hashtable that looks something along the lines of what is
         # shown in the example inside the variable declaration. This hashtable is what each thread returns and is what
         # will later be stored into $fileResults
         $scanResults = @{
         #                  "scanResults":  {
         #                      "BadStrings":  {
         #                          "Score":  5,
         #                          "Indicators":  [
         #                              "\"Upload\"",
         #                              "@eval(",
         #                              "(is_dir(",
         #                              "(base64_decode(",
         #                              "(str_rot13("
         #                          ]
         #                      },
         #                      "Entropy":  {
         #                          "Score":  6.109601908390065,
         #                          "Indicators":  "No indicators exist for entropy hits."
         #                      }
         #                  }
         #
         }
         # This property contains the full path including filename e.g. c:\users\test\webshell.php
         $fullPath = $file.FullName
         # Some functions require the full content of the file rather than line by line reading
         # so we extract is once here and pass it around
         $content =  [System.IO.File]::ReadAlltext("$fullpath")
         # We use this later to detect really small files that have a bad string
         $linecount = ($content | Measure-Object -Line).Lines 
         # Large file slow down execution significantly, we trim the file to stop extremely large files from bogging us down
         # while still leaving enough of the file to detect web shells (hopefully).
         # This doesnt effect String matching as we do that line by line. it only effects functions that we pass $content to.
         # Like Get-Entropy for example, which shouldnt hopefully be effected too much by the limit.
         $len = $content.length
         if ($len -ge 50000) {
            $content = $content.substring(0,50000)
         }
         # This one's pretty simple. Attackers who base64 encode a payload or hex encode it or whatever sometimes
         # kind of stop there as far as obfuscation goes and just plop the whole string down on one line.
         # Coding practices prevent (haha) developers from doing this (haha) so we look for very large strings
         # on a single line here. In practice, some devs throw massive slabs of code without a line break.
         # To stop from FP'ing so much we set a threshold that must be met before we declare the line long enough to be webshell
         $LongestLineLength, $longestLine = Get-LongestLineCount $fullpath
         # Specifically 'whitelisting' svg lines here as they are  commonly placed on one line and are massive enough to trigger.
         if ($longestLineLength -ge $lineCountThreshold) 
         {
            Write-Verbose "WEBSHELLFOUND -LONGLINECOUNT: A Single line was $LongestLineLength characters long in $file`n" 
            $scanResults["LongLine"] = [pscustomobject]@{
                Score = $longestLineLength
                Indicators =  $longestLine.Substring(0,100)
            }
         }

         # I tested this tool against hideshell (https://github.com/0verl0ad/HideShell) and all the previous
         # Checks missed for various reason. Hideshell base64 encodes your webshell and then breaks up that
         # base64 string into lots and lots of substrings that it rebuilts like this:
         #     z .= "GJSRP"
         #     z .= "APVKS"
         #     z .= "PKWMV"
         # And so on for thousands of lines. I figured a clever way to defeat this kind of obfuscation
         # is to look for variables beings "added to" (.= or +=) and then count how many times each variable
         # gets added to. To rebuild a base64 string into one variable with small chunks, you HAVE to add to it
         # LOTS of times. So we look for variables that are added to LOTS of time. I dont really see regular
         # scripts adding to a variable 400 times in one script but bad guys definitely do that.
         $varCount, $var = Get-VariableUsageCount $file.fullname
         # I've found so far that the threshold should be atleast above 50. Its not uncommon for a normal php scipt
         # to play with a variable 40 odd times in different spots (like building html request or w/e).
         if ($varCount -ge $varUsageThreshold) 
         {
            Write-Verbose "WEBSHELL FOUND - OVERLYUSEDVARIABLE: $varCount - $var  `tin file $fullPath`n"
            $scanResults["overusedVar"] = [pscustomobject]@{
                    Score = $varCount
                    Indicators =  $var
                    }
         }
         # check the number of string matches in this file against our array of regex's at the top of scriptblock
         $badStringCount, $stringsMatched = Find-BadStrings $file.fullname
         
         # Nearly all legitimate files use atleast one of our blacklisted strings
         # so we set a threshold that must be met before declaring something a webshell.
         # helps lower FP counts dramatically.
         # We also check for $linecount to be less than or equal to 5 with atleast one badstring.
         # This should catch those sneaky 1-2 line webshells that bypass AV so often. 
         if ($badStringCount -ge $stringThreshold -or ($badStringCount -ge 1 -and $lineCount -le 10)) 
         {
            Write-Verbose "WEBSHELLFOUND BADSTRINGS: Found $badStringCount bad strings for $file`n"
            # We dont want to scan entropy unless we have to, so if we reach our entropy threshold
            # call it a webshell match and move on.
            $scanResults["BadStrings"] =  [pscustomobject]@{
                    Score = $badStringCount
                    Indicators = $stringsMatched
                    }
         }
         # I saw quite a few webshells with something like bXZaseXZ64CZ_decoXZde followed by a str_replace("XZ", "")
         # to deobfuscate the base64_decode call. This function will take any files that have a str_replace function (its
         # harder to obfuscate that since you need it to remove the obfuscation) and attempt to perform the string replacement
         # to expose any potentially obfuscated calls that would have otherwise been missed. 
         # TODO: Try to cover str_replace that uses variables. we can only deobfuscate when strings are used in str_replace atm
         if ($content -match "str_replace\([`"'][\w\W]+[`"'],[`"']{2},") 
         {
            $strRepMatches, $strRepCount = Find-StrReplaceObfuscation $content
            # We check our newly returned "bad strings count" against the old $badstringcount from before the deobfuscation attempt
            # was conducted. If we get even one new bad string we arecalling it a webshell since we shouldn't really ever find a bad string
            # by doing a string replace. Thats just too shady.
            if ($strRepCount -gt $badStringCount) 
            {
                Write-Verbose "WEBSHELLFOUND DEOBFUSCATEDSTRINGS: deobfuscation found $badStringCount bad strings for $file`n" 
                # Always return if we find a webshell. Speed is an issue with powershell
                $scanResults["StrReplace"] =  [pscustomobject]@{
                    Score = $strRepCount
                    Indicators =  $strRepMatches
                    }
            }
         }
         # Entropy may help us find encoded or encrypted data chunks that commonly reside in webshells.
         $entropyScore = Get-Entropy $content
         # Super low entropy scores could indicate single line webshells, so we look for that. Still testing if this theory is sane though
         # once entropy is high enough we also dont FP too much on regular web files, so we look for high entropy too.
         if ($entropyScore -ge $entThresholdUpper -or $entropyScore -le $entThresholdLower) 
         {
            Write-Verbose "WEBSHELLFOUND HIGHENTROPY:  Entropy score of $entropyScore for $file`n"
            $scanResults["Entropy"] =  [pscustomobject]@{
                      Score = $entropyScore
                      Indicators =  "No indicators exist for entropy hits."}
         }
         Write-Verbose "-------------FILECHECKCOMPLETE--------------`n"
         
         if ($testFile -eq $true -and $scanresults.count -eq 0) {
            Write-Debug "MISSED: $fullpath"
         }
         return $scanResults
      }
      Catch
      {
         Write-Error "CHECKFILE: "$_.Exception
         Break
      }
   }
   End
   {
        $timeTaken = $stopwatch.Elapsed.TotalSeconds
        Write-Information "CHECKFILE TIME:`tfunction executed in $timeTaken Seconds`n"
   }
}

function normalize {
    param(
        [int]$enteredValue,
        [int]$minEntry, 
        [int]$maxEntry 
    )
    # I needed a way to normalize the scores returned from each detection method since some
    # return 128,000 and others return 6.11 and I wanted to aggregrate them to determine the 
    # "InterestingScore".
    # I took the answer from the below link and changed it to powershell. Does the trick.
    # https://stackoverflow.com/questions/42518950/how-do-i-properly-normalize-very-large-numbers-algorithmic-ally-to-a-relatively
    $normalizedMin = 1
    $normalizedMax = 10

    $mx = ($enteredValue-$minEntry)/($maxEntry-$minEntry)
    $preshiftNormalized = $mx*($normalizedMax-$normalizedMin)
    $shiftedNormalized = $preshiftNormalized + $normalizedMin
    # Added this in because if the enteredValue is too high, this function returns a number greater than the normalizedMax should allow
    if ($shiftedNormalized -gt $normalizedMax)
    {
        $shiftedNormalized = $normalizedMax
    }
    
    return $shiftedNormalized

}

Function New-InterestingScore {
    param(
        $results
    )
    # This function is meant to solve the "OK your dumb script returned 400 hits. What one should I look at first" Question.
    # We normalize each detection methods score to between 1-10, add some extra weighting for better detection methods and then
    # Sum them all up to determine the "Interesting Score" for each file. The higher the score, the more we want to look at it.
    # This is used to build the "Top files to look at" table in the results
    foreach ($file in $results){
        $score = 0
        foreach ($method in $file.scanresults.Keys) {
            $methodScore = $file.ScanResults["$method"].Score 
            if ($method -eq "BadStrings")  { $NormScore = normalize $methodScore 0 50 }
            if ($method -eq "Entropy")     { $normScore = $methodScore }
            if ($method -eq "strReplace")  { $normScore = (normalize $methodScore 0 5) + 4}
            if ($method -eq "LongLine")    { $normScore = (normalize $methodScore 0 100000) + 2 }
            if ($method -eq "overusedVar") { $normScore = (normalize $methodScore 0 1000) + 4 }
            
            Write-Verbose "NORMALIZED $method score $methodscore to $NormScore"
            $score += $normScore
        }
        $score = [Math]::Round($score, 2)
        $file | Add-Member -MemberType NoteProperty -Name "InterestingScore" -Value $score
       
    }
    return $results
}
# Function to create thread-safe hashtable (requires .NET 4.0+):
function New-ThreadSafeTypedDictionary([Type] $KeyType, [Type] $ValueType)
{
    $GenericDict = [System.Collections.Concurrent.ConcurrentDictionary``2]
    $GenericDict = $GenericDict.MakeGenericType( @($KeyType, $ValueType) )
    New-Object -TypeName $GenericDict 
}



#-----------------------------------------------------------[Execution]------------------------------------------------------------
function main
{
$stopwatch.Start()

# Results hashtable to store the result objects for each file scanned
$results = New-Object -TypeName psobject
# Grab all the files for both our hunt path and test path that we are going to scan through later
$files = Get-ChildItem -Path $huntPath -include $fileTypes -Recurse
if ($testPath) {
    $testfiles = Get-ChildItem -Path $testPath -Include $filetypes -Recurse
}
# We grab this for displaying stats at the end of the scan and for division to figure out our write-progress.
if ($testpath ) {
    $filecount = $files.count + $testfiles.Count 
} else {
    $filecount = $files.count 
}
if ($filecount -eq 0 ) {
   Write-Error "No files found. Confirm your -huntPath"
   Exit 
}

# The next block of code is setting up the multithreading stuff we need.
# Big thanks to https://github.com/SamuelArnold/StarKill3r/blob/master/Star%20Killer/Star%20Killer/bin/Debug/Scripts/SANS-SEC505-master/scripts/Day1-PowerShell/Runspace-Pool-Examples.ps1
# Most of this is taken from there, with only minor tweaking needed.
# Create array to hold all of our runspaces
$runspaces = @()
# This is our threadsafe Hashtable we'll pass into each thread. Each thread will scan a seperate file
# and store its results into this hashtable. 
$fileResults = New-ThreadSafeTypedDictionary -KeyType 'String' -ValueType 'object' 
# Define the initial session state for our pool
$SessionState = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
$SessionState.ApartmentState = 'STA'
$SessionState.ThreadOptions = 'ReuseThread'
# Add a variable to the session state pool that can be used to pass in data and/or collect output:
# ArgumentList = name of the variable, initial value of variable, an optional description
$SessionVar = New-Object -TypeName System.Management.Automation.Runspaces.SessionStateVariableEntry -ArgumentList @("fileResults", $fileResults, 'detection method hits for each file') 
$SessionState.Variables.Add( $SessionVar ) 
$funcs = @(
   "Find-BadStrings", 
   "Get-Entropy",
   "Get-VariableUsageCount", 
   "Get-LongestLineCount",
   "Search-Shells"
)
foreach ($func in $funcs) {
   #Get body of function
   $definition = Get-Content Function:/$func
   #Create a sessionstate funciton entry
   $sessionStateFunction = New-Object System.Management.Automation.Runspaces.SessionStateFunctionEntry -ArgumentList $func, $definition
   $sessionState.Commands.Add($sessionStateFunction)
}
# Create between 1 (min) and $maxthreads runspaces in a pool, with an initial session state, in the current PowerShell host:
$Pool = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspacePool(1, $maxThreads, $SessionState, $Host)
# Open the runspace pool:
$Pool.Open()

# Loop through all of our huntpath and testpath (if selected) files and create a runspace for each one, passing in any relevant switches
# and then invoking the runspace.
Write-Host "Creating Hunt Path runspaces" -ForegroundColor Yellow
# We set testfile to false so that each thread in huntpath can note in its results that this file is part of huntpath.
# this lets us seperate legitimate files vs test webshells later on.
$testFile = $false
foreach ($file in $files) 
{
   # Generate the runspaces for all of the files in our huntpath
   $runspace = [PowerShell]::Create()
   [void]$runspace.AddScript($scriptblock)
   [void]$runspace.AddArgument($file)
   [void]$runspace.AddArgument($detailed)
   [void]$runspace.AddArgument($speedInfo)
   [void]$runspace.AddArgument($missedShells)
   [void]$runspace.AddArgument($testfile)
   $runspace.runspacepool = $pool
   $runspaces += $runspace.BeginInvoke()
}
if ($testPath) {
   # now set testfile to true to so we can tag all of these as testfiles within the threads returned results.
   # again, this lets us seperate test files from legit files later so we can determine whether "caught" files are test ones or not.
   $testFile = $true
   # Generate the runspaces for all of the files in our testpath
   foreach ($file in $testfiles) 
   {
      $runspace = [PowerShell]::Create()
      [void]$runspace.AddScript($scriptblock)
      [void]$runspace.AddArgument($file)
      [void]$runspace.AddArgument($detailed)
      [void]$runspace.AddArgument($speedInfo)
      [void]$runspace.AddArgument($missedShells)
      [void]$runspace.AddArgument($testfile)
      $runspace.runspacepool = $pool
      $runspaces += $runspace.BeginInvoke()
   }
}
write-host "All Runspaces created. Waiting for results to return." -ForegroundColor Green

#Loop Forever until all of our runspaces have reported in as complete
while ($true)
{
    
   $runspaces | Where-Object { $_.IsCompleted -eq $False } | ForEach-Object { Continue }
   # Clean up objects and break out of the While loop: 
   $runspaces | ForEach-Object { $_.AsyncWaitHandle.Close() }
   $runspaces = @() 
   $runspace = $null 
   $pool.Close()
   $pool.Dispose() 
   Break 
}

# Trim fileresults down to just what the threads returned. We could skip this if we used some kind of thread safe array.
# But I'm still learning.
$fileResults = $fileResults.Values
# We want to go through each detection methods results and pull out the top 10 results by score.
# this lets us give the user a starting point for analysis. If we scan 3000 files and get 100 "webshells"
# its hard to know which ones to check first and this tool probably just wouldnt be used at that point.
# top 10's provide a "check here first" short list.
# We have to store each detection method in $checkedMethods as we check it so that we only check each method once.
$checkedMethods = @()
# Initially I was trying to just append straight to the final $results object as we went. 
# but that messed the json output in a way I didnt like. So we store the top10's in an intermediary variable.
$top10Results = New-object -TypeName psobject
# Loop through each detection method so we can build up a top 10 list for each method that fired during this scan
foreach ($method in $fileResults.scanresults.Keys) 
{
    # Not sure why, but empty methods kept popping up, so we just skip them as an easy fix 
    if (!($checkedMethods.Contains($method)) -and $null -ne $method ) 
    {
        $top10 = $fileresults.GetEnumerator() | Where-Object {$_.scanResults.$method.Score -gt 0 } | Sort-Object { $_.ScanResults.$method.Score } -Descending | Select-Object -First 10
        # Gotta build up the key string before we make the custom object so that the key can be dynamically named
        $top10string = "top10$method"
        $top10results | add-member -memberType NoteProperty -Name $top10string -value $top10
        # Add it to the list so we dont check it again
        $checkedMethods += $method
    }
}

# Generate an "Interesting Score" for every file we had a hit on. This will build our "Top files to look at" table at the end.
$fileResults = New-InterestingScore $fileResults
# Build the top ten most interesting files to look at based on the previously generated "Interesting Score"
$top10Interesting = $fileResults.GetEnumerator() | Sort-Object { $_.InterestingScore} -Descending | Select-Object -Property @{Name="Score"; Expression={$_.interestingscore}}, filename, filepath -First 10
# This is why set set $testfile and pass it to each runspace. We look for which files are testfiles and which ones arent to generate a count of
# how many files we matches against in our huntpath vs our testpath
$HitCount = ($fileResults.GetEnumerator() | Where-Object {$_.istestfile -eq $false}).count
$TestFileHits = ($fileResults.GetEnumerator() | Where-Object {$_.istestfile -eq $true}).count

# Build everything we have discovered into our final variable that we can JSONify later
$results | Add-member -MemberType NoteProperty -Name "TotalFilesScanned" -Value $files.count
$results | Add-Member -MemberType NoteProperty -Name "HitCount" -Value $HitCount
$results | Add-member -MemberType NoteProperty -Name "TotalTestFilesScanned" -Value $testFiles.count
$results | Add-member -MemberType NoteProperty -Name "TestFileHitCount" -Value $testFileHits
$results | Add-Member -MemberType NoteProperty -Name "Top10overall" -Value $top10Interesting
$results | Add-member -MemberType NoteProperty -Name "Top10PerMethod" -Value $top10Results
$results | Add-member -MemberType NoteProperty -Name "FileResults" -Value $fileResults
$results | Add-Member -MemberType NoteProperty -Name "TestFileResults" -Value $TestFileHits

#-----------------------------------------------------------[Print/Log Results]------------------------------------------------------------

# Print out of Top 10 Files Overall Table
Write-Host "`n`n`t`tTop files to look at" -ForegroundColor Green
$results.Top10overall  | Format-Table
# Print out our Top Results for each detection method Table
$results.top10PerMethod | Get-Member -type NoteProperty | foreach-object {
    $method = $_.name
    $methodShort = $_.name.Tostring().Replace("top10", "")
    write-host "`t`tTop results for"$methodShort -foregroundcolor green
    $results.top10PerMethod.$method   | Select-Object -Property @{Name="Score"; Expression={[Math]::Round($_.ScanResults.$methodShort.Score, 2) }},
                                                     filename,
                                                    filepath | Format-Table
}
# Print some Stats
write-host "`tHunt Directory:" $results.HitCount"/"$results.TotalFilesScanned -Foregroundcolor green
if ($testPath) {
    write-host "`tTest Directory:" $results.TestFileHitCount"/"$results.TotalTestFilesScanned -Foregroundcolor yellow
}
# Write out the time taken so we can try and go faster in the future. SPEEEEED
write-host "`n`t`tFinished Scanning in "$stopwatch.elapsed.TotalSeconds "Seconds" -Foregroundcolor Green
# Output to json is the user wants.
if ($json) {
   $results | convertTo-Json -depth 5  | set-content $json
}
[System.GC]::Collect()
# Reset the preferences if we changed them. Just in case the user wants to keep using the same terminal
if ($speedInfo) {
$InformationPreference = "SilentlyContinue" 
}
if ($detailed) {
    $VerbosePreference = "SilentlyContinue"
}
if ($missedShells) {
    $DebugPreference = "SilentlyContinue"
}
}
Main