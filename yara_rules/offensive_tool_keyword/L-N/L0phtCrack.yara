rule L0phtCrack
{
    meta:
        description = "Detection patterns for the tool 'L0phtCrack' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "L0phtCrack"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: L0phtCrack attempts to crack Windows passwords from hashes which it can obtain (given proper access) from stand-alone Windows workstations. networked servers. primary domain controllers. or Active Directory. In some cases it can sniff the hashes off the wire. It also has numerous methods of generating password guesses (dictionary. brute force. etc). LC5 was discontinued by Symantec in 2006. then re-acquired by the original L0pht guys and reborn as LC6 in 2009. For free alternatives. consider ophcrack. Cain and Abel. or John the Ripper. For downloads and more information. visit the L0phtCrack homepage.
        // Reference: http://www.l0phtcrack.com/
        $string1 = "L0phtCrack" nocase ascii wide

    condition:
        any of them
}
