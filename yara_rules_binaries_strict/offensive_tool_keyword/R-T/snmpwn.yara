rule snmpwn
{
    meta:
        description = "Detection patterns for the tool 'snmpwn' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "snmpwn"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: SNMPwn is an SNMPv3 user enumerator and attack tool. It is a legitimate security tool designed to be used by security professionals and penetration testers against hosts you have permission to test. It takes advantage of the fact that SNMPv3 systems will respond with Unknown user name when an SNMP user does not exist. allowing us to cycle through large lists of users to find the ones that do.
        // Reference: https://github.com/hatlord/snmpwn
        $string1 = /\/snmpwn\.git/ nocase ascii wide
        // Description: SNMPwn is an SNMPv3 user enumerator and attack tool. It is a legitimate security tool designed to be used by security professionals and penetration testers against hosts you have permission to test. It takes advantage of the fact that SNMPv3 systems will respond with Unknown user name when an SNMP user does not exist. allowing us to cycle through large lists of users to find the ones that do
        // Reference: https://github.com/hatlord/snmpwn
        $string2 = /\/snmpwn\.rb/ nocase ascii wide
        // Description: SNMPwn is an SNMPv3 user enumerator and attack tool. It is a legitimate security tool designed to be used by security professionals and penetration testers against hosts you have permission to test. It takes advantage of the fact that SNMPv3 systems will respond with  Unknown user name  when an SNMP user does not exist. allowing us to cycle through large lists of users to find the ones that do
        // Reference: https://github.com/hatlord/snmpwn
        $string3 = "hatlord/snmpwn" nocase ascii wide
        // Description: SNMPwn is an SNMPv3 user enumerator and attack tool. It is a legitimate security tool designed to be used by security professionals and penetration testers against hosts you have permission to test. It takes advantage of the fact that SNMPv3 systems will respond with  Unknown user name  when an SNMP user does not exist. allowing us to cycle through large lists of users to find the ones that do
        // Reference: https://github.com/hatlord/snmpwn
        $string4 = /snmpwn\s.{0,100}passwords\.txt/ nocase ascii wide
        // Description: SNMPwn is an SNMPv3 user enumerator and attack tool. It is a legitimate security tool designed to be used by security professionals and penetration testers against hosts you have permission to test. It takes advantage of the fact that SNMPv3 systems will respond with Unknown user name when an SNMP user does not exist. allowing us to cycle through large lists of users to find the ones that do.
        // Reference: https://github.com/hatlord/snmpwn
        $string5 = /snmpwn\.rb.{0,100}\s\-\-hosts\s/ nocase ascii wide
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
