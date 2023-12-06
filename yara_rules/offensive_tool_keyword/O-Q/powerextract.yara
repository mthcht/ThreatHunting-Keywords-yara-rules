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
        $string1 = /\s\-PathToDMP\s.{0,1000}\.dmp/ nocase ascii wide
        // Description: This tool is able to parse memory dumps of the LSASS process without any additional tools (e.g. Debuggers) or additional sideloading of mimikatz. It is a pure PowerShell implementation for parsing and extracting secrets (LSA / MSV and Kerberos) of the LSASS process
        // Reference: https://github.com/powerseb/PowerExtract
        $string2 = /\/PowerExtract\.git/ nocase ascii wide
        // Description: This tool is able to parse memory dumps of the LSASS process without any additional tools (e.g. Debuggers) or additional sideloading of mimikatz. It is a pure PowerShell implementation for parsing and extracting secrets (LSA / MSV and Kerberos) of the LSASS process
        // Reference: https://github.com/powerseb/PowerExtract
        $string3 = /\/PowerExtract\.git/ nocase ascii wide
        // Description: This tool is able to parse memory dumps of the LSASS process without any additional tools (e.g. Debuggers) or additional sideloading of mimikatz. It is a pure PowerShell implementation for parsing and extracting secrets (LSA / MSV and Kerberos) of the LSASS process
        // Reference: https://github.com/powerseb/PowerExtract
        $string4 = /Get\-KIWI_KERBEROS_LOGON_SESSION/ nocase ascii wide
        // Description: This tool is able to parse memory dumps of the LSASS process without any additional tools (e.g. Debuggers) or additional sideloading of mimikatz. It is a pure PowerShell implementation for parsing and extracting secrets (LSA / MSV and Kerberos) of the LSASS process
        // Reference: https://github.com/powerseb/PowerExtract
        $string5 = /Invoke\-PowerExtract/ nocase ascii wide
        // Description: This tool is able to parse memory dumps of the LSASS process without any additional tools (e.g. Debuggers) or additional sideloading of mimikatz. It is a pure PowerShell implementation for parsing and extracting secrets (LSA / MSV and Kerberos) of the LSASS process
        // Reference: https://github.com/powerseb/PowerExtract
        $string6 = /PowerExtract\-main\.zip/ nocase ascii wide
        // Description: This tool is able to parse memory dumps of the LSASS process without any additional tools (e.g. Debuggers) or additional sideloading of mimikatz. It is a pure PowerShell implementation for parsing and extracting secrets (LSA / MSV and Kerberos) of the LSASS process
        // Reference: https://github.com/powerseb/PowerExtract
        $string7 = /powerseb\/PowerExtract/ nocase ascii wide
        // Description: This tool is able to parse memory dumps of the LSASS process without any additional tools (e.g. Debuggers) or additional sideloading of mimikatz. It is a pure PowerShell implementation for parsing and extracting secrets (LSA / MSV and Kerberos) of the LSASS process
        // Reference: https://github.com/powerseb/PowerExtract
        $string8 = /powerseb\/PowerExtract/ nocase ascii wide

    condition:
        any of them
}
