rule powerextract
{
    meta:
        description = "Detection patterns for the tool 'powerextract' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "powerextract"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: This tool is able to parse memory dumps of the LSASS process without any additional tools (e.g. Debuggers) or additional sideloading of mimikatz. It is a pure PowerShell implementation for parsing and extracting secrets (LSA / MSV and Kerberos) of the LSASS process
        // Reference: https://github.com/powerseb/PowerExtract
        $string1 = /.{0,1000}\s\-PathToDMP\s.{0,1000}\.dmp.{0,1000}/ nocase ascii wide
        // Description: This tool is able to parse memory dumps of the LSASS process without any additional tools (e.g. Debuggers) or additional sideloading of mimikatz. It is a pure PowerShell implementation for parsing and extracting secrets (LSA / MSV and Kerberos) of the LSASS process
        // Reference: https://github.com/powerseb/PowerExtract
        $string2 = /.{0,1000}\/PowerExtract\.git.{0,1000}/ nocase ascii wide
        // Description: This tool is able to parse memory dumps of the LSASS process without any additional tools (e.g. Debuggers) or additional sideloading of mimikatz. It is a pure PowerShell implementation for parsing and extracting secrets (LSA / MSV and Kerberos) of the LSASS process
        // Reference: https://github.com/powerseb/PowerExtract
        $string3 = /.{0,1000}\/PowerExtract\.git.{0,1000}/ nocase ascii wide
        // Description: This tool is able to parse memory dumps of the LSASS process without any additional tools (e.g. Debuggers) or additional sideloading of mimikatz. It is a pure PowerShell implementation for parsing and extracting secrets (LSA / MSV and Kerberos) of the LSASS process
        // Reference: https://github.com/powerseb/PowerExtract
        $string4 = /.{0,1000}Get\-KIWI_KERBEROS_LOGON_SESSION.{0,1000}/ nocase ascii wide
        // Description: This tool is able to parse memory dumps of the LSASS process without any additional tools (e.g. Debuggers) or additional sideloading of mimikatz. It is a pure PowerShell implementation for parsing and extracting secrets (LSA / MSV and Kerberos) of the LSASS process
        // Reference: https://github.com/powerseb/PowerExtract
        $string5 = /.{0,1000}Invoke\-PowerExtract.{0,1000}/ nocase ascii wide
        // Description: This tool is able to parse memory dumps of the LSASS process without any additional tools (e.g. Debuggers) or additional sideloading of mimikatz. It is a pure PowerShell implementation for parsing and extracting secrets (LSA / MSV and Kerberos) of the LSASS process
        // Reference: https://github.com/powerseb/PowerExtract
        $string6 = /.{0,1000}PowerExtract\-main\.zip.{0,1000}/ nocase ascii wide
        // Description: This tool is able to parse memory dumps of the LSASS process without any additional tools (e.g. Debuggers) or additional sideloading of mimikatz. It is a pure PowerShell implementation for parsing and extracting secrets (LSA / MSV and Kerberos) of the LSASS process
        // Reference: https://github.com/powerseb/PowerExtract
        $string7 = /.{0,1000}powerseb\/PowerExtract.{0,1000}/ nocase ascii wide
        // Description: This tool is able to parse memory dumps of the LSASS process without any additional tools (e.g. Debuggers) or additional sideloading of mimikatz. It is a pure PowerShell implementation for parsing and extracting secrets (LSA / MSV and Kerberos) of the LSASS process
        // Reference: https://github.com/powerseb/PowerExtract
        $string8 = /.{0,1000}powerseb\/PowerExtract.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
