rule wce
{
    meta:
        description = "Detection patterns for the tool 'wce' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "wce"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Windows Credentials Editor
        // Reference: https://www.kali.org/tools/wce/
        $string1 = "/returnvar/wce/" nocase ascii wide
        // Description: Windows Credentials Editor
        // Reference: https://www.kali.org/tools/wce/
        $string2 = "/share/windows-resources/wce" nocase ascii wide
        // Description: Windows Credentials Editor
        // Reference: https://www.kali.org/tools/wce/
        $string3 = /\/wce32\.exe/ nocase ascii wide
        // Description: Windows Credentials Editor
        // Reference: https://www.kali.org/tools/wce/
        $string4 = /\/wce64\.exe/ nocase ascii wide
        // Description: Windows Credentials Editor
        // Reference: https://www.kali.org/tools/wce/
        $string5 = /\/wce\-beta\.zip/ nocase ascii wide
        // Description: Windows Credentials Editor
        // Reference: https://www.kali.org/tools/wce/
        $string6 = /\\wce32\.exe/ nocase ascii wide
        // Description: Windows Credentials Editor
        // Reference: https://www.kali.org/tools/wce/
        $string7 = /\\wce64\.exe/ nocase ascii wide
        // Description: Windows Credentials Editor
        // Reference: https://www.kali.org/tools/wce/
        $string8 = /\\wce\-beta\.zip/ nocase ascii wide
        // Description: Windows Credentials Editor
        // Reference: https://www.kali.org/tools/wce/
        $string9 = "apt install wce" nocase ascii wide
        // Description: Windows Credentials Editor
        // Reference: https://www.kali.org/tools/wce/
        $string10 = "wce -i 3e5 -s " nocase ascii wide
        // Description: Windows Credentials Editor
        // Reference: https://www.kali.org/tools/wce/
        $string11 = /wce.{0,100}getlsasrvaddr\.exe/ nocase ascii wide
        // Description: Windows Credentials Editor
        // Reference: https://www.kali.org/tools/wce/
        $string12 = /wce\-master\.zip/ nocase ascii wide
        // Description: Windows Credentials Editor
        // Reference: https://www.kali.org/tools/wce/
        $string13 = /wce\-universal\.exe/ nocase ascii wide
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
