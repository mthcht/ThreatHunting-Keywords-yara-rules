rule mssqlproxy
{
    meta:
        description = "Detection patterns for the tool 'mssqlproxy' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "mssqlproxy"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: mssqlproxy is a toolkit aimed to perform Lateral Movement in restricted environments through a compromised Microsoft SQL Server via socket reuse
        // Reference: https://github.com/blackarrowsec/mssqlproxy
        $string1 = /\/mssqlproxy\.git/ nocase ascii wide
        // Description: mssqlproxy is a toolkit aimed to perform Lateral Movement in restricted environments through a compromised Microsoft SQL Server via socket reuse
        // Reference: https://github.com/blackarrowsec/mssqlproxy
        $string2 = /blackarrowsec\/mssqlproxy/ nocase ascii wide
        // Description: mssqlproxy is a toolkit aimed to perform Lateral Movement in restricted environments through a compromised Microsoft SQL Server via socket reuse
        // Reference: https://github.com/blackarrowsec/mssqlproxy
        $string3 = /mssqlproxy\-master/ nocase ascii wide
        // Description: mssqlproxy is a toolkit aimed to perform Lateral Movement in restricted environments through a compromised Microsoft SQL Server via socket reuse
        // Reference: https://github.com/blackarrowsec/mssqlproxy
        $string4 = /reciclador\.cpp/ nocase ascii wide
        // Description: mssqlproxy is a toolkit aimed to perform Lateral Movement in restricted environments through a compromised Microsoft SQL Server via socket reuse
        // Reference: https://github.com/blackarrowsec/mssqlproxy
        $string5 = /reciclador\.dll/ nocase ascii wide
        // Description: mssqlproxy is a toolkit aimed to perform Lateral Movement in restricted environments through a compromised Microsoft SQL Server via socket reuse
        // Reference: https://github.com/blackarrowsec/mssqlproxy
        $string6 = /reciclador\.vcxproj/ nocase ascii wide

    condition:
        any of them
}
