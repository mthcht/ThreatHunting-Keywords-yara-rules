rule smbscan
{
    meta:
        description = "Detection patterns for the tool 'smbscan' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "smbscan"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: SMBScan is a tool to enumerate file shares on an internal network.
        // Reference: https://github.com/jeffhacks/smbscan
        $string1 = /\sCRITICAL\]\sSuspicous\sfile\:\s\\\\/ nocase ascii wide
        // Description: SMBScan is a tool to enumerate file shares on an internal network.
        // Reference: https://github.com/jeffhacks/smbscan
        $string2 = /\ssmbscan\.py\s/ nocase ascii wide
        // Description: SMBScan is a tool to enumerate file shares on an internal network.
        // Reference: https://github.com/jeffhacks/smbscan
        $string3 = /\/smbscan\-.{0,100}\.csv/ nocase ascii wide
        // Description: SMBScan is a tool to enumerate file shares on an internal network.
        // Reference: https://github.com/jeffhacks/smbscan
        $string4 = /\/smbscan\-.{0,100}\.log/ nocase ascii wide
        // Description: SMBScan is a tool to enumerate file shares on an internal network.
        // Reference: https://github.com/jeffhacks/smbscan
        $string5 = /\/smbscan\.git/ nocase ascii wide
        // Description: SMBScan is a tool to enumerate file shares on an internal network.
        // Reference: https://github.com/jeffhacks/smbscan
        $string6 = /\/smbscan\.py/ nocase ascii wide
        // Description: SMBScan is a tool to enumerate file shares on an internal network.
        // Reference: https://github.com/jeffhacks/smbscan
        $string7 = /\\smbscan\-.{0,100}\.csv/ nocase ascii wide
        // Description: SMBScan is a tool to enumerate file shares on an internal network.
        // Reference: https://github.com/jeffhacks/smbscan
        $string8 = /\\smbscan\-.{0,100}\.log/ nocase ascii wide
        // Description: SMBScan is a tool to enumerate file shares on an internal network.
        // Reference: https://github.com/jeffhacks/smbscan
        $string9 = /\\smbscan\.py/ nocase ascii wide
        // Description: SMBScan is a tool to enumerate file shares on an internal network.
        // Reference: https://github.com/jeffhacks/smbscan
        $string10 = "a4d92518de887211fcc6d0f0c011336140fa14d69a505223947a088cec3a9c0f" nocase ascii wide
        // Description: SMBScan is a tool to enumerate file shares on an internal network.
        // Reference: https://github.com/jeffhacks/smbscan
        $string11 = "dc9978d7-6299-4c5a-a22d-a039cdc716ea" nocase ascii wide
        // Description: SMBScan is a tool to enumerate file shares on an internal network.
        // Reference: https://github.com/jeffhacks/smbscan
        $string12 = /impacket\.smbconnection\.SMBConnection/ nocase ascii wide
        // Description: SMBScan is a tool to enumerate file shares on an internal network.
        // Reference: https://github.com/jeffhacks/smbscan
        $string13 = "jeffhacks/smbscan" nocase ascii wide
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
