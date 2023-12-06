rule samba
{
    meta:
        description = "Detection patterns for the tool 'samba' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "samba"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: The net command is one of the new features of Samba-3 and is an attempt to provide a useful tool for the majority of remote management operations necessary for common tasks. It is used by attackers to find users list
        // Reference: https://www.samba.org/samba/docs/old/Samba3-HOWTO/NetCommand.html
        $string1 = /net\srpc\sgroup\smembers\s\'Domain\sUsers\'\s\-W\s/ nocase ascii wide

    condition:
        any of them
}
