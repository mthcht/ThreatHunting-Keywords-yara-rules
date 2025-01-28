rule PewPewPew
{
    meta:
        description = "Detection patterns for the tool 'PewPewPew' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PewPewPew"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: host a script on a PowerShell webserver, invoke the IEX download cradle to download/execute the target code and post the results back to the server
        // Reference: https://github.com/PowerShellEmpire/PowerTools
        $string1 = "8b27ef8f7cbae47922e672618e39abe7fa626c7405a67b12d7a88c1da8b06cad" nocase ascii wide
        // Description: host a script on a PowerShell webserver, invoke the IEX download cradle to download/execute the target code and post the results back to the server
        // Reference: https://github.com/PowerShellEmpire/PowerTools
        $string2 = "95f9539c17bfa24ee0d7206b1fb2b195885b94e82d6bd7276bfccf2f0ceb9ac4" nocase ascii wide
        // Description: host a script on a PowerShell webserver, invoke the IEX download cradle to download/execute the target code and post the results back to the server
        // Reference: https://github.com/PowerShellEmpire/PowerTools
        $string3 = "a591699874d0a2c26c1d9e47561ee2a3043fc3ea458c09a7ab8a24a25150cd0a" nocase ascii wide
        // Description: host a script on a PowerShell webserver, invoke the IEX download cradle to download/execute the target code and post the results back to the server
        // Reference: https://github.com/PowerShellEmpire/PowerTools
        $string4 = "f392e058d65cc84f23773a88424d5a9e6a6987f790c52e0fb032e8538b5aec36" nocase ascii wide
        // Description: host a script on a PowerShell webserver, invoke the IEX download cradle to download/execute the target code and post the results back to the server
        // Reference: https://github.com/PowerShellEmpire/PowerTools
        $string5 = /Invoke\-MassCommand\.ps1/ nocase ascii wide
        // Description: host a script on a PowerShell webserver, invoke the IEX download cradle to download/execute the target code and post the results back to the server
        // Reference: https://github.com/PowerShellEmpire/PowerTools
        $string6 = "Invoke-MassMimikatz" nocase ascii wide
        // Description: host a script on a PowerShell webserver, invoke the IEX download cradle to download/execute the target code and post the results back to the server
        // Reference: https://github.com/PowerShellEmpire/PowerTools
        $string7 = /Invoke\-MassSearch\.ps1/ nocase ascii wide
        // Description: host a script on a PowerShell webserver, invoke the IEX download cradle to download/execute the target code and post the results back to the server
        // Reference: https://github.com/PowerShellEmpire/PowerTools
        $string8 = /Invoke\-MassTokens\.ps1/ nocase ascii wide
        // Description: host a script on a PowerShell webserver, invoke the IEX download cradle to download/execute the target code and post the results back to the server
        // Reference: https://github.com/PowerShellEmpire/PowerTools
        $string9 = /Invoke\-TokenManipulation\s\-CreateProcess\s.{0,100}cmd\.exe/ nocase ascii wide
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
