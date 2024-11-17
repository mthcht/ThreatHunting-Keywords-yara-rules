rule canisrufus
{
    meta:
        description = "Detection patterns for the tool 'canisrufus' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "canisrufus"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A stealthy Python based Windows backdoor that uses Github as a command and control server
        // Reference: https://github.com/maldevel/canisrufus
        $string1 = /\scanisrufus\.py/ nocase ascii wide
        // Description: A stealthy Python based Windows backdoor that uses Github as a command and control server
        // Reference: https://github.com/maldevel/canisrufus
        $string2 = /\sshellcode_generate\.py/ nocase ascii wide
        // Description: A stealthy Python based Windows backdoor that uses Github as a command and control server
        // Reference: https://github.com/maldevel/canisrufus
        $string3 = /\s\-start\-keylogger/ nocase ascii wide
        // Description: A stealthy Python based Windows backdoor that uses Github as a command and control server
        // Reference: https://github.com/maldevel/canisrufus
        $string4 = /\s\-stop\-keylogger/ nocase ascii wide
        // Description: A stealthy Python based Windows backdoor that uses Github as a command and control server
        // Reference: https://github.com/maldevel/canisrufus
        $string5 = /\swindows\/meterpreter\/reverse_tcp/ nocase ascii wide
        // Description: A stealthy Python based Windows backdoor that uses Github as a command and control server
        // Reference: https://github.com/maldevel/canisrufus
        $string6 = /\/canisrufus\.git/ nocase ascii wide
        // Description: A stealthy Python based Windows backdoor that uses Github as a command and control server
        // Reference: https://github.com/maldevel/canisrufus
        $string7 = /\/canisrufus\.py/ nocase ascii wide
        // Description: A stealthy Python based Windows backdoor that uses Github as a command and control server
        // Reference: https://github.com/maldevel/canisrufus
        $string8 = /\/shellcode_generate\.py/ nocase ascii wide
        // Description: A stealthy Python based Windows backdoor that uses Github as a command and control server
        // Reference: https://github.com/maldevel/canisrufus
        $string9 = /\\canisrufus\.py/ nocase ascii wide
        // Description: A stealthy Python based Windows backdoor that uses Github as a command and control server
        // Reference: https://github.com/maldevel/canisrufus
        $string10 = /\\shellcode_generate\.py/ nocase ascii wide
        // Description: A stealthy Python based Windows backdoor that uses Github as a command and control server
        // Reference: https://github.com/maldevel/canisrufus
        $string11 = /54cbfafed88c0b70ede4fe88d02a9de61aee9eb2017c54e7ec0b1c97d755db35/ nocase ascii wide
        // Description: A stealthy Python based Windows backdoor that uses Github as a command and control server
        // Reference: https://github.com/maldevel/canisrufus
        $string12 = /836d7d2ecfbe96f0be128c9b1a4cdbb8e138c502c2420e91713c8b2621aa474a/ nocase ascii wide
        // Description: A stealthy Python based Windows backdoor that uses Github as a command and control server
        // Reference: https://github.com/maldevel/canisrufus
        $string13 = /generate_powershell_shellcode\(/ nocase ascii wide
        // Description: A stealthy Python based Windows backdoor that uses Github as a command and control server
        // Reference: https://github.com/maldevel/canisrufus
        $string14 = /maldevel\/canisrufus/ nocase ascii wide
        // Description: A stealthy Python based Windows backdoor that uses Github as a command and control server
        // Reference: https://github.com/maldevel/canisrufus
        $string15 = /msfvenom\s\-p\s/ nocase ascii wide
        // Description: A stealthy Python based Windows backdoor that uses Github as a command and control server
        // Reference: https://github.com/maldevel/canisrufus
        $string16 = /\'User\-Agent\'\:\'CanisRufus\'/ nocase ascii wide
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
