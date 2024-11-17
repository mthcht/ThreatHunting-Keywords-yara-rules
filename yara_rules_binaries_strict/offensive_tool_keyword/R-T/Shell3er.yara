rule Shell3er
{
    meta:
        description = "Detection patterns for the tool 'Shell3er' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Shell3er"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: PowerShell Reverse Shell
        // Reference: https://github.com/yehia-mamdouh/Shell3er
        $string1 = /\sShell3er\.ps1/ nocase ascii wide
        // Description: PowerShell Reverse Shell
        // Reference: https://github.com/yehia-mamdouh/Shell3er
        $string2 = /\/Shell3er\.git/ nocase ascii wide
        // Description: PowerShell Reverse Shell
        // Reference: https://github.com/yehia-mamdouh/Shell3er
        $string3 = /\/Shell3er\.ps1/ nocase ascii wide
        // Description: PowerShell Reverse Shell
        // Reference: https://github.com/yehia-mamdouh/Shell3er/blob/main/Shell3er.ps1
        $string4 = /\/Shell3er\// nocase ascii wide
        // Description: PowerShell Reverse Shell
        // Reference: https://github.com/yehia-mamdouh/Shell3er
        $string5 = /\\Shell3er\.ps1/ nocase ascii wide
        // Description: PowerShell Reverse Shell
        // Reference: https://github.com/yehia-mamdouh/Shell3er
        $string6 = /\\Shell3er\-main/ nocase ascii wide
        // Description: PowerShell Reverse Shell
        // Reference: https://github.com/yehia-mamdouh/Shell3er
        $string7 = /6334665cbd227e91e2fe4517cc5bb0e6f4163aa4ae10430e034df836287dc339/ nocase ascii wide
        // Description: PowerShell Reverse Shell
        // Reference: https://github.com/yehia-mamdouh/Shell3er
        $string8 = /cABvAHcAZQByAHMAaABlAGwAbAAuAGUAeABlACAALQBFAHgAZQBjAHUAdABpAG8AbgBQAG8AbABpAGMAeQAgAEIAeQBwAGEAcwBzACAALQBGAGkAbABlACAAQwA6AFwAUAByAG8AZwByAGEAbQBEAGEAdABhAFwAUwBoAGUAbABsADMAZQByAC4AcABzADEA/ nocase ascii wide
        // Description: PowerShell Reverse Shell
        // Reference: https://github.com/yehia-mamdouh/Shell3er/blob/main/Shell3er.ps1
        $string9 = /cABvAHcAZQByAHMAaABlAGwAbAAuAGUAeABlACAALQBFAHgAZQBjAHUAdABpAG8AbgBQAG8AbABpAGMAeQAgAEIAeQBwAGEAcwBzACAALQBGAGkAbABlACAAQwA6AFwAUAByAG8AZwByAGEAbQBEAGEAdABhAFwAUwBoAGUAbABsADMAZQByAC4AcABzADEA/ nocase ascii wide
        // Description: PowerShell Reverse Shell
        // Reference: https://github.com/yehia-mamdouh/Shell3er/blob/main/Shell3er.ps1
        $string10 = /nc\s\-nlvp\s4444/ nocase ascii wide
        // Description: PowerShell Reverse Shell
        // Reference: https://github.com/yehia-mamdouh/Shell3er
        $string11 = /SABLAEMAVQA6AFwAUwBPAEYAVABXAEEAUgBFAFwATQBpAGMAcgBvAHMAbwBmAHQAXABXAGkAbgBkAG8AdwBzAFwAQwB1AHIAcgBlAG4AdABWAGUAcgBzAGkAbwBuAFwAUgB1AG4A/ nocase ascii wide
        // Description: PowerShell Reverse Shell
        // Reference: https://github.com/yehia-mamdouh/Shell3er/blob/main/Shell3er.ps1
        $string12 = /Shell3er\.ps1/ nocase ascii wide
        // Description: PowerShell Reverse Shell
        // Reference: https://github.com/yehia-mamdouh/Shell3er
        $string13 = /Welcome\sto\sthe\sMrvar0x\sPowerShell\sRemote\sShell\!/ nocase ascii wide
        // Description: PowerShell Reverse Shell
        // Reference: https://github.com/yehia-mamdouh/Shell3er
        $string14 = /yehia\-mamdouh\/Shell3er/ nocase ascii wide
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
