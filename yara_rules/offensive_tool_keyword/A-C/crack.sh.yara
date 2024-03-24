rule crack_sh
{
    meta:
        description = "Detection patterns for the tool 'crack.sh' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "crack.sh"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: crack.sh THE WORLD???S FASTEST DES CRACKER. Used by attackers to submit passwords to crack
        // Reference: https://crack.sh/get-cracking/
        $string1 = /\/crack\.sh\/get\-cracking\// nocase ascii wide

    condition:
        any of them
}
