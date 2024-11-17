rule AMSI_Provider
{
    meta:
        description = "Detection patterns for the tool 'AMSI-Provider' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "AMSI-Provider"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A fake AMSI Provider which can be used for persistence
        // Reference: https://github.com/netbiosX/AMSI-Provider
        $string1 = /\/AMSI\-Provider\.git/ nocase ascii wide
        // Description: A fake AMSI Provider which can be used for persistence
        // Reference: https://github.com/netbiosX/AMSI-Provider
        $string2 = /\\AmsiProvider\.cpp/ nocase ascii wide
        // Description: A fake AMSI Provider which can be used for persistence
        // Reference: https://github.com/netbiosX/AMSI-Provider
        $string3 = /\\AmsiProvider\.sln/ nocase ascii wide
        // Description: A fake AMSI Provider which can be used for persistence
        // Reference: https://github.com/netbiosX/AMSI-Provider
        $string4 = /\\AMSI\-Provider\-main/ nocase ascii wide
        // Description: A fake AMSI Provider which can be used for persistence
        // Reference: https://github.com/netbiosX/AMSI-Provider
        $string5 = /58B32FCA\-F385\-4500\-9A8E\-7CBA1FC9BA13/ nocase ascii wide
        // Description: A fake AMSI Provider which can be used for persistence
        // Reference: https://github.com/netbiosX/AMSI-Provider
        $string6 = /7a9a81c7ef99897281466ea06c14886335cf8d4c835f15aeb1e3a2c7c1d0e760/ nocase ascii wide
        // Description: A fake AMSI Provider which can be used for persistence
        // Reference: https://github.com/netbiosX/AMSI-Provider
        $string7 = /90bf7beb921839957e7977851f01e757346d2b4f672e6a08b04e57878cd6efbf/ nocase ascii wide
        // Description: A fake AMSI Provider which can be used for persistence
        // Reference: https://github.com/netbiosX/AMSI-Provider
        $string8 = /b4a7045568cb78f48f42b93f528e14ef24f8dc3bf878af0b94ca22c5df546da5/ nocase ascii wide
        // Description: A fake AMSI Provider which can be used for persistence
        // Reference: https://github.com/netbiosX/AMSI-Provider
        $string9 = /netbiosX\/AMSI\-Provider/ nocase ascii wide
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
