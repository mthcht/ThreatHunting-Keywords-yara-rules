rule samdump2
{
    meta:
        description = "Detection patterns for the tool 'samdump2' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "samdump2"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Retrieves syskey and extract hashes from Windows 2k/NT/XP/Vista SAM.
        // Reference: https://salsa.debian.org/pkg-security-team/samdump2
        $string1 = /\/samdump2/ nocase ascii wide
        // Description: Retrieves syskey and extract hashes from Windows 2k/NT/XP/Vista SAM.
        // Reference: https://salsa.debian.org/pkg-security-team/samdump2
        $string2 = /install\ssamdump2/ nocase ascii wide
        // Description: Retrieves syskey and extract hashes from Windows 2k/NT/XP/Vista SAM.
        // Reference: https://salsa.debian.org/pkg-security-team/samdump2
        $string3 = /samdump2\s/ nocase ascii wide
        // Description: Retrieves syskey and extract hashes from Windows 2k/NT/XP/Vista SAM.
        // Reference: https://salsa.debian.org/pkg-security-team/samdump2
        $string4 = /samdump2\.c/ nocase ascii wide

    condition:
        any of them
}