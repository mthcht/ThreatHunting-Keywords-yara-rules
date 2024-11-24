rule csvde
{
    meta:
        description = "Detection patterns for the tool 'csvde' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "csvde"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: exports data from Active Directory Domain Services (AD DS) using files that store data in the comma-separated value (CSV) format
        // Reference: https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc732101(v=ws.11)
        $string1 = "csvde -f " nocase ascii wide
        // Description: exports data from Active Directory Domain Services (AD DS) using files that store data in the comma-separated value (CSV) format
        // Reference: https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc732101(v=ws.11)
        $string2 = /csvde\s\-r\s.{0,1000}\s\-f\s/ nocase ascii wide
        // Description: exports data from Active Directory Domain Services (AD DS) using files that store data in the comma-separated value (CSV) format
        // Reference: https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc732101(v=ws.11)
        $string3 = /csvde\.exe\s\-f\s/ nocase ascii wide
        // Description: exports data from Active Directory Domain Services (AD DS) using files that store data in the comma-separated value (CSV) format
        // Reference: https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc732101(v=ws.11)
        $string4 = /csvde\.exe\s\-r\s.{0,1000}\s\-f\s/ nocase ascii wide
        // Description: exports data from Active Directory Domain Services (AD DS) using files that store data in the comma-separated value (CSV) format
        // Reference: https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc732101(v=ws.11)
        $string5 = /csvde\.exe\\"\s\-f\s/ nocase ascii wide

    condition:
        any of them
}
