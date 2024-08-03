rule gmer
{
    meta:
        description = "Detection patterns for the tool 'gmer' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "gmer"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: rootkit detector abused by attackers to disable security software
        // Reference: gmer.net
        $string1 = /\/gmer\.exe/ nocase ascii wide
        // Description: rootkit detector abused by attackers to disable security software
        // Reference: gmer.net
        $string2 = /\\gmer\.exe/ nocase ascii wide
        // Description: rootkit detector abused by attackers to disable security software
        // Reference: gmer.net
        $string3 = /\\gmer64\.pdb/ nocase ascii wide
        // Description: rootkit detector abused by attackers to disable security software
        // Reference: gmer.net
        $string4 = /\\Release\\gmer\.pdb/ nocase ascii wide
        // Description: rootkit detector abused by attackers to disable security software
        // Reference: gmer.net
        $string5 = /e8a3e804a96c716a3e9b69195db6ffb0d33e2433af871e4d4e1eab3097237173/ nocase ascii wide
        // Description: rootkit detector abused by attackers to disable security software
        // Reference: gmer.net
        $string6 = /http\:\/\/www\.gmer\.net\/\#files/ nocase ascii wide
        // Description: rootkit detector abused by attackers to disable security software
        // Reference: gmer.net
        $string7 = /http\:\/\/www2\.gmer\.net\/download/ nocase ascii wide
        // Description: rootkit detector abused by attackers to disable security software
        // Reference: gmer.net
        $string8 = /http\:\/\/www2\.gmer\.net\/gmer\.zip/ nocase ascii wide

    condition:
        any of them
}
