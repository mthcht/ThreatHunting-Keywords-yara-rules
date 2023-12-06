rule pdbedit
{
    meta:
        description = "Detection patterns for the tool 'pdbedit' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "pdbedit"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Sets the smbpasswd listing format. It will make pdbedit list the users in the database - printing out the account fields in a format compatible with the smbpasswd file format.
        // Reference: https://github.com/RoseSecurity/Red-Teaming-TTPs/blob/main/Linux.md
        $string1 = /pdbedit\s\-L\s\-v/ nocase ascii wide
        // Description: Enables the verbose listing format. It causes pdbedit to list the users in the database - printing out the account fields in a descriptive format
        // Reference: https://github.com/RoseSecurity/Red-Teaming-TTPs/blob/main/Linux.md
        $string2 = /pdbedit\s\-L\s\-w/ nocase ascii wide

    condition:
        any of them
}
