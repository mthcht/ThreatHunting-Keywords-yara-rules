rule autoNTDS
{
    meta:
        description = "Detection patterns for the tool 'autoNTDS' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "autoNTDS"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: autoNTDS is an automation script designed to simplify the process of dumping and cracking NTDS hashes using secretsdump.py and hashcat
        // Reference: https://github.com/hmaverickadams/autoNTDS
        $string1 = /\sautoNTDS\.py/ nocase ascii wide
        // Description: autoNTDS is an automation script designed to simplify the process of dumping and cracking NTDS hashes using secretsdump.py and hashcat
        // Reference: https://github.com/hmaverickadams/autoNTDS
        $string2 = /\s\-\-crack\s.{0,1000}\s\-\-ntds/ nocase ascii wide
        // Description: autoNTDS is an automation script designed to simplify the process of dumping and cracking NTDS hashes using secretsdump.py and hashcat
        // Reference: https://github.com/hmaverickadams/autoNTDS
        $string3 = /\s\-\-ntds\s.{0,1000}\s\-crack\s/ nocase ascii wide
        // Description: autoNTDS is an automation script designed to simplify the process of dumping and cracking NTDS hashes using secretsdump.py and hashcat
        // Reference: https://github.com/hmaverickadams/autoNTDS
        $string4 = /\s\-\-passwords\-to\-users\s.{0,1000}hash/ nocase ascii wide
        // Description: autoNTDS is an automation script designed to simplify the process of dumping and cracking NTDS hashes using secretsdump.py and hashcat
        // Reference: https://github.com/hmaverickadams/autoNTDS
        $string5 = /\/autoNTDS\.git/ nocase ascii wide
        // Description: autoNTDS is an automation script designed to simplify the process of dumping and cracking NTDS hashes using secretsdump.py and hashcat
        // Reference: https://github.com/hmaverickadams/autoNTDS
        $string6 = /\/autoNTDS\.py/ nocase ascii wide
        // Description: autoNTDS is an automation script designed to simplify the process of dumping and cracking NTDS hashes using secretsdump.py and hashcat
        // Reference: https://github.com/hmaverickadams/autoNTDS
        $string7 = /\/cracked\-users\.txt/ nocase ascii wide
        // Description: autoNTDS is an automation script designed to simplify the process of dumping and cracking NTDS hashes using secretsdump.py and hashcat
        // Reference: https://github.com/hmaverickadams/autoNTDS
        $string8 = /\\autoNTDS\.py/ nocase ascii wide
        // Description: autoNTDS is an automation script designed to simplify the process of dumping and cracking NTDS hashes using secretsdump.py and hashcat
        // Reference: https://github.com/hmaverickadams/autoNTDS
        $string9 = "5df2061e118e67da27199797b696b33b0176f35d155b2a1204b4fd11ea6d25bb" nocase ascii wide
        // Description: autoNTDS is an automation script designed to simplify the process of dumping and cracking NTDS hashes using secretsdump.py and hashcat
        // Reference: https://github.com/hmaverickadams/autoNTDS
        $string10 = "hmaverickadams/autoNTDS" nocase ascii wide
        // Description: autoNTDS is an automation script designed to simplify the process of dumping and cracking NTDS hashes using secretsdump.py and hashcat
        // Reference: https://github.com/hmaverickadams/autoNTDS
        $string11 = /Passwords\sto\susers\scomplete\.\sPlease\ssee\scracked\-users\.txt/ nocase ascii wide

    condition:
        any of them
}
