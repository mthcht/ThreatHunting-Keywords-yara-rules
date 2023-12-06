rule psloggedon
{
    meta:
        description = "Detection patterns for the tool 'psloggedon' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "psloggedon"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: PsLoggedOn is an applet that displays both the locally logged on users and users logged on via resources for either the local computer. or a remote one
        // Reference: https://learn.microsoft.com/en-us/sysinternals/downloads/psloggedon
        $string1 = /PsLoggedon\.exe/ nocase ascii wide
        // Description: PsLoggedOn is an applet that displays both the locally logged on users and users logged on via resources for either the local computer. or a remote one
        // Reference: https://learn.microsoft.com/en-us/sysinternals/downloads/psloggedon
        $string2 = /PsLoggedon64\.exe/ nocase ascii wide

    condition:
        any of them
}
