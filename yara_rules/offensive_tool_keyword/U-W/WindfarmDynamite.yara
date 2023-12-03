rule WindfarmDynamite
{
    meta:
        description = "Detection patterns for the tool 'WindfarmDynamite' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "WindfarmDynamite"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: WindfarmDynamite is a proof-of-concept for code injection using the Windows Notification Facility (WNF). Of interest here is that this avoids suspect thread orchestration APIs (like CreateRemoteThread)
        // Reference: https://github.com/FuzzySecurity/Sharp-Suite/tree/master/WindfarmDynamite
        $string1 = /.{0,1000}WindfarmDynamite\.cdproj.{0,1000}/ nocase ascii wide
        // Description: WindfarmDynamite is a proof-of-concept for code injection using the Windows Notification Facility (WNF). Of interest here is that this avoids suspect thread orchestration APIs (like CreateRemoteThread)
        // Reference: https://github.com/FuzzySecurity/Sharp-Suite/tree/master/WindfarmDynamite
        $string2 = /.{0,1000}WindfarmDynamite\.exe.{0,1000}/ nocase ascii wide
        // Description: WindfarmDynamite is a proof-of-concept for code injection using the Windows Notification Facility (WNF). Of interest here is that this avoids suspect thread orchestration APIs (like CreateRemoteThread)
        // Reference: https://github.com/FuzzySecurity/Sharp-Suite/tree/master/WindfarmDynamite
        $string3 = /.{0,1000}WindfarmDynamite\.sln.{0,1000}/ nocase ascii wide
        // Description: WindfarmDynamite is a proof-of-concept for code injection using the Windows Notification Facility (WNF). Of interest here is that this avoids suspect thread orchestration APIs (like CreateRemoteThread)
        // Reference: https://github.com/FuzzySecurity/Sharp-Suite/tree/master/WindfarmDynamite
        $string4 = /.{0,1000}WNFarmDynamite_h\.cs.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
