rule mssqlproxy
{
    meta:
        description = "Detection patterns for the tool 'mssqlproxy' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "mssqlproxy"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: mssqlproxy is a toolkit aimed to perform lateral movement in restricted environments through a compromised Microsoft SQL Server via socket reuse
        // Reference: https://github.com/blackarrowsec/mssqlproxy
        $string1 = /.{0,1000}\/mssqlproxy\.git.{0,1000}/ nocase ascii wide
        // Description: mssqlproxy is a toolkit aimed to perform lateral movement in restricted environments through a compromised Microsoft SQL Server via socket reuse
        // Reference: https://github.com/blackarrowsec/mssqlproxy
        $string2 = /.{0,1000}blackarrowsec\/mssqlproxy.{0,1000}/ nocase ascii wide
        // Description: mssqlproxy is a toolkit aimed to perform lateral movement in restricted environments through a compromised Microsoft SQL Server via socket reuse
        // Reference: https://github.com/blackarrowsec/mssqlproxy
        $string3 = /.{0,1000}mssqlproxy\-master.{0,1000}/ nocase ascii wide
        // Description: mssqlproxy is a toolkit aimed to perform lateral movement in restricted environments through a compromised Microsoft SQL Server via socket reuse
        // Reference: https://github.com/blackarrowsec/mssqlproxy
        $string4 = /.{0,1000}reciclador\.cpp.{0,1000}/ nocase ascii wide
        // Description: mssqlproxy is a toolkit aimed to perform lateral movement in restricted environments through a compromised Microsoft SQL Server via socket reuse
        // Reference: https://github.com/blackarrowsec/mssqlproxy
        $string5 = /.{0,1000}reciclador\.dll.{0,1000}/ nocase ascii wide
        // Description: mssqlproxy is a toolkit aimed to perform lateral movement in restricted environments through a compromised Microsoft SQL Server via socket reuse
        // Reference: https://github.com/blackarrowsec/mssqlproxy
        $string6 = /.{0,1000}reciclador\.vcxproj.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
