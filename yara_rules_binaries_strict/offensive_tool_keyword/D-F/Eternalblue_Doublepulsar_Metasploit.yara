rule Eternalblue_Doublepulsar_Metasploit
{
    meta:
        description = "Detection patterns for the tool 'Eternalblue-Doublepulsar-Metasploit' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Eternalblue-Doublepulsar-Metasploit"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: doublepulsa vulnerability exploit DoublePulsar is a backdoor implant tool developed by the U.S. National Security Agencys (NSA) Equation Group that was leaked by The Shadow Brokers in early 2017.[3] The tool infected more than 200.000 Microsoft Windows computers in only a few weeks.[4][5][3][6][7] and was used alongside EternalBlue in the May 2017 WannaCry ransomware attack.[8][9][10] A variant of DoublePulsar was first seen in the wild in March 2016. as discovered by Symantec. [11]
        // Reference: https://github.com/Telefonica/Eternalblue-Doublepulsar-Metasploit
        $string1 = "Eternalblue-Doublepulsar" nocase ascii wide
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
