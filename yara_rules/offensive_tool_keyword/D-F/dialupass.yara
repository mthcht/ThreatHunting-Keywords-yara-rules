rule dialupass
{
    meta:
        description = "Detection patterns for the tool 'dialupass' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "dialupass"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: This utility enumerates all dialup/VPN entries on your computers. and displays their logon details: User Name. Password. and Domain. You can use it to recover a lost password of your Internet connection or VPN.
        // Reference: https://www.nirsoft.net/utils/dialupass.html
        $string1 = /.{0,1000}Dialupass\.exe.{0,1000}/ nocase ascii wide
        // Description: This utility enumerates all dialup/VPN entries on your computers. and displays their logon details: User Name. Password. and Domain. You can use it to recover a lost password of your Internet connection or VPN.
        // Reference: https://www.nirsoft.net/utils/dialupass.html
        $string2 = /.{0,1000}Dialupass\.zip.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
