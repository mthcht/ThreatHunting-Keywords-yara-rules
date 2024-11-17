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
        $metadata_regex_import = /\bimport\s+[a-zA-Z0-9_.]+\b/ nocase
        $metadata_regex_function = /function\s+[a-zA-Z_][a-zA-Z0-9_]*\(/ nocase ascii
        $metadata_regex_php = /<\?php/ nocase ascii
        $metadata_regex_createobject = /(CreateObject|WScript\.)/ nocase ascii
        $metadata_regex_script = /<script\b/ nocase ascii
        $metadata_regex_javascript = /(let\s|const\s|function\s|document\.|console\.)/ nocase ascii
        $metadata_regex_powershell = /(Write-Host|Get-[a-zA-Z]+|Invoke-|param\(|\.SYNOPSIS)/ nocase ascii
        $metadata_regex_batch = /@(echo\s|call\s|set\s|goto\s|if\s|for\s|rem\s)/ nocase ascii
        $metadata_regex_shebang = /^#!\// nocase ascii

    condition:
        ((filesize < 20MB and (
            uint16(0) == 0x5a4d or // Windows binary
            uint16(0) == 0x457f or // Linux ELF
            uint32be(0) == 0x7f454c46 or uint16(0) == 0xfeca or uint16(0) == 0xfacf or uint32(0) == 0xbebafeca or // macOS binary
            uint32(0) == 0x504B0304 or // Android APK, JAR
            uint32(0) == 0xCAFEBABE or // Java Class, Mach-O Universal Binary
            uint32(0) == 0x4D534346 or // Windows Cabinet File
            uint32(0) == 0xD0CF11E0 or // MSI Installer Package
            uint16(0) == 0x2321 or // Shebang (#!)
            uint16(0) == 0x3c3f // PHP and other script
        )) and any of ($string*)) or
        (filesize < 2MB and
        (
            any of ($string*) and
            for any of ($metadata_regex_*) : ( @ <= 20000 )
        ))
}
