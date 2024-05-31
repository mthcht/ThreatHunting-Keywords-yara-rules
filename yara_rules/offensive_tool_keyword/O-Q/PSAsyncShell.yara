rule PSAsyncShell
{
    meta:
        description = "Detection patterns for the tool 'PSAsyncShell' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PSAsyncShell"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: PowerShell Asynchronous TCP Reverse Shell
        // Reference: https://github.com/JoelGMSec/PSAsyncShell
        $string1 = /\sPSAsyncShell\.ps1/ nocase ascii wide
        // Description: PowerShell Asynchronous TCP Reverse Shell
        // Reference: https://github.com/JoelGMSec/PSAsyncShell
        $string2 = /\sPSAsyncShell\.sh/ nocase ascii wide
        // Description: PowerShell Asynchronous TCP Reverse Shell
        // Reference: https://github.com/JoelGMSec/PSAsyncShell
        $string3 = /\/PSAsyncShell\.git/ nocase ascii wide
        // Description: PowerShell Asynchronous TCP Reverse Shell
        // Reference: https://github.com/JoelGMSec/PSAsyncShell
        $string4 = /\/PSAsyncShell\.ps1/ nocase ascii wide
        // Description: PowerShell Asynchronous TCP Reverse Shell
        // Reference: https://github.com/JoelGMSec/PSAsyncShell
        $string5 = /\/PSAsyncShell\.sh/ nocase ascii wide
        // Description: PowerShell Asynchronous TCP Reverse Shell
        // Reference: https://github.com/JoelGMSec/PSAsyncShell
        $string6 = /\/PSAsyncShell\-main/ nocase ascii wide
        // Description: PowerShell Asynchronous TCP Reverse Shell
        // Reference: https://github.com/JoelGMSec/PSAsyncShell
        $string7 = /\[\+\]\sPSAsyncShell\sOK\!/ nocase ascii wide
        // Description: PowerShell Asynchronous TCP Reverse Shell
        // Reference: https://github.com/JoelGMSec/PSAsyncShell
        $string8 = /\\PSAsyncShell\.ps1/ nocase ascii wide
        // Description: PowerShell Asynchronous TCP Reverse Shell
        // Reference: https://github.com/JoelGMSec/PSAsyncShell
        $string9 = /\\PSAsyncShell\.sh/ nocase ascii wide
        // Description: PowerShell Asynchronous TCP Reverse Shell
        // Reference: https://github.com/JoelGMSec/PSAsyncShell
        $string10 = /\\PSAsyncShell\-main/ nocase ascii wide
        // Description: PowerShell Asynchronous TCP Reverse Shell
        // Reference: https://github.com/JoelGMSec/PSAsyncShell
        $string11 = /c88583cefd0d79a7db5a22290081218d5d9e2ce83de1ca17b8242f7fc74b2535/ nocase ascii wide
        // Description: PowerShell Asynchronous TCP Reverse Shell
        // Reference: https://github.com/JoelGMSec/PSAsyncShell
        $string12 = /cc49a6056b1f2216c0986cd16b01d2fb5bc03664a2818a5ce3ecdc6a3132707c/ nocase ascii wide
        // Description: PowerShell Asynchronous TCP Reverse Shell
        // Reference: https://github.com/JoelGMSec/PSAsyncShell
        $string13 = /JoelGMSec\/PSAsyncShell/ nocase ascii wide
        // Description: PowerShell Asynchronous TCP Reverse Shell
        // Reference: https://github.com/JoelGMSec/PSAsyncShell
        $string14 = /PSAsyncShell\sby\s\@JoelGMSec/ nocase ascii wide

    condition:
        any of them
}
