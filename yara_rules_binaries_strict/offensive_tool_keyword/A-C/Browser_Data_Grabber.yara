rule Browser_Data_Grabber
{
    meta:
        description = "Detection patterns for the tool 'Browser Data Grabber' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Browser Data Grabber"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: credential access tool used by the Dispossessor ransomware group
        // Reference: https://github.com/n37sn4k3/BrowserDataGrabber
        $string1 = /\/BrowserDataGrabber\.git/ nocase ascii wide
        // Description: credential access tool used by the Dispossessor ransomware group
        // Reference: https://github.com/n37sn4k3/BrowserDataGrabber
        $string2 = /\\BrowserDataGrabber\.pdb/ nocase ascii wide
        // Description: credential access tool used by the Dispossessor ransomware group
        // Reference: https://github.com/n37sn4k3/BrowserDataGrabber
        $string3 = /\\BrowserDataGrabber\\/ nocase ascii wide
        // Description: credential access tool used by the Dispossessor ransomware group
        // Reference: https://github.com/n37sn4k3/BrowserDataGrabber
        $string4 = ">BrowserDataGrabber<" nocase ascii wide
        // Description: credential access tool used by the Dispossessor ransomware group
        // Reference: https://github.com/n37sn4k3/BrowserDataGrabber
        $string5 = "1830c05bde7c4d7b795968d4e3c25ecb3dd98763662b1d85fd4abfbbf8e5b660" nocase ascii wide
        // Description: credential access tool used by the Dispossessor ransomware group
        // Reference: https://github.com/n37sn4k3/BrowserDataGrabber
        $string6 = "1d389e53c658a3919dfcd0d1e3dd08c34a2e875eb1520ec0b9648e43e25eaabc" nocase ascii wide
        // Description: credential access tool used by the Dispossessor ransomware group
        // Reference: https://github.com/n37sn4k3/BrowserDataGrabber
        $string7 = "8173d4d17cb728e6f2c5e2ce8124ce7eb0f459dc62085bcaab786abf1f6b37a7" nocase ascii wide
        // Description: credential access tool used by the Dispossessor ransomware group
        // Reference: https://github.com/n37sn4k3/BrowserDataGrabber
        $string8 = "a9d6d8e1051e28d933a3979f20e8fd7eb85611d2014502d093aa879681bbbc26" nocase ascii wide
        // Description: credential access tool used by the Dispossessor ransomware group
        // Reference: https://github.com/n37sn4k3/BrowserDataGrabber
        $string9 = /BrowserDataGrabber\.exe/ nocase ascii wide
        // Description: credential access tool used by the Dispossessor ransomware group
        // Reference: https://github.com/n37sn4k3/BrowserDataGrabber
        $string10 = /BrowserDataGrabber\-master\.zip/ nocase ascii wide
        // Description: credential access tool used by the Dispossessor ransomware group
        // Reference: https://github.com/n37sn4k3/BrowserDataGrabber
        $string11 = "f2691b74-129f-4ac2-a88a-db4b0f36b609" nocase ascii wide
        // Description: credential access tool used by the Dispossessor ransomware group
        // Reference: https://github.com/n37sn4k3/BrowserDataGrabber
        $string12 = "n37sn4k3/BrowserDataGrabber" nocase ascii wide
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
