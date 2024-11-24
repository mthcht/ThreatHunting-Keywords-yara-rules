rule traitor
{
    meta:
        description = "Detection patterns for the tool 'traitor' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "traitor"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Automatically exploit low-hanging fruit to pop a root shell. Linux privilege escalation made easy
        // Reference: https://github.com/liamg/traitor
        $string1 = /\/backdoor\/traitor\.go/ nocase ascii wide
        // Description: Automatically exploit low-hanging fruit to pop a root shell. Linux privilege escalation made easy
        // Reference: https://github.com/liamg/traitor
        $string2 = /\/cve.{0,100}\/exploit\.go/ nocase ascii wide
        // Description: Automatically exploit low-hanging fruit to pop a root shell. Linux privilege escalation made easy
        // Reference: https://github.com/liamg/traitor
        $string3 = /\/exploits\/.{0,100}\.go/ nocase ascii wide
        // Description: Automatically exploit low-hanging fruit to pop a root shell. Linux privilege escalation made easy
        // Reference: https://github.com/liamg/traitor
        $string4 = /\/gtfobins\.go/ nocase ascii wide
        // Description: Automatically exploit low-hanging fruit to pop a root shell. Linux privilege escalation made easy
        // Reference: https://github.com/liamg/traitor
        $string5 = /\/internal\/pipe\/pipe\.go/ nocase ascii wide
        // Description: Automatically exploit low-hanging fruit to pop a root shell. Linux privilege escalation made easy
        // Reference: https://github.com/liamg/traitor
        $string6 = /\/payloads\/payloads\.go/ nocase ascii wide
        // Description: Automatically exploit low-hanging fruit to pop a root shell. Linux privilege escalation made easy
        // Reference: https://github.com/liamg/traitor
        $string7 = /\/pkg\/state\/sudoers\.go/ nocase ascii wide
        // Description: Automatically exploit low-hanging fruit to pop a root shell. Linux privilege escalation made easy
        // Reference: https://github.com/liamg/traitor
        $string8 = /\/shell\/password\.go/ nocase ascii wide
        // Description: Automatically exploit low-hanging fruit to pop a root shell. Linux privilege escalation made easy
        // Reference: https://github.com/liamg/traitor
        $string9 = /\|base64\s\-d\s\>\s\/tmp\/traitor/ nocase ascii wide
        // Description: Automatically exploit low-hanging fruit to pop a root shell. Linux privilege escalation made easy
        // Reference: https://github.com/liamg/traitor
        $string10 = /cmd\/backdoor\.go/ nocase ascii wide
        // Description: Automatically exploit low-hanging fruit to pop a root shell. Linux privilege escalation made easy
        // Reference: https://github.com/liamg/traitor
        $string11 = /cmd\/setuid\.go/ nocase ascii wide
        // Description: Automatically exploit low-hanging fruit to pop a root shell. Linux privilege escalation made easy
        // Reference: https://github.com/liamg/traitor
        $string12 = /go\sget\s\-u\s.{0,100}traitor\/cmd\/traitor/ nocase ascii wide
        // Description: Automatically exploit low-hanging fruit to pop a root shell. Linux privilege escalation made easy
        // Reference: https://github.com/liamg/traitor
        $string13 = "liamg/traitor" nocase ascii wide
        // Description: Automatically exploit low-hanging fruit to pop a root shell. Linux privilege escalation made easy
        // Reference: https://github.com/liamg/traitor
        $string14 = "traitor -a " nocase ascii wide
        // Description: Automatically exploit low-hanging fruit to pop a root shell. Linux privilege escalation made easy
        // Reference: https://github.com/liamg/traitor
        $string15 = "traitor --any " nocase ascii wide
        // Description: Automatically exploit low-hanging fruit to pop a root shell. Linux privilege escalation made easy
        // Reference: https://github.com/liamg/traitor
        $string16 = "traitor -e " nocase ascii wide
        // Description: Automatically exploit low-hanging fruit to pop a root shell. Linux privilege escalation made easy
        // Reference: https://github.com/liamg/traitor
        $string17 = "traitor --exploit" nocase ascii wide
        // Description: Automatically exploit low-hanging fruit to pop a root shell. Linux privilege escalation made easy
        // Reference: https://github.com/liamg/traitor
        $string18 = "traitor -p " nocase ascii wide
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
