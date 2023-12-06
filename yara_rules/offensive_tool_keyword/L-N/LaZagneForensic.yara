rule LaZagneForensic
{
    meta:
        description = "Detection patterns for the tool 'LaZagneForensic' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "LaZagneForensic"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Windows passwords decryption from dump files
        // Reference: https://github.com/AlessandroZ/LaZagneForensic
        $string1 = /LaZagneForensic/ nocase ascii wide

    condition:
        any of them
}
