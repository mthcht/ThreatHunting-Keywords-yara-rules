rule dsregcmd
{
    meta:
        description = "Detection patterns for the tool 'dsregcmd' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "dsregcmd"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: dsregcmd.exe to check the SSO state which might indicate preparation for abusing Azure AD tokens
        // Reference: https://github.com/Mayyhem/Maestro
        $string1 = /dsregcmd\.exe\s\/status/ nocase ascii wide

    condition:
        any of them
}
