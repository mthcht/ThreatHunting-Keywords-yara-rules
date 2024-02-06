rule AD_Miner
{
    meta:
        description = "Detection patterns for the tool 'AD_Miner' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "AD_Miner"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: AD Miner is an Active Directory audit tool that leverages cypher queries to crunch data from the #Bloodhound graph database to uncover security weaknesses
        // Reference: https://github.com/Mazars-Tech/AD_Miner
        $string1 = /\/AD_Miner\.git/ nocase ascii wide
        // Description: AD Miner is an Active Directory audit tool that leverages cypher queries to crunch data from the #Bloodhound graph database to uncover security weaknesses
        // Reference: https://github.com/Mazars-Tech/AD_Miner
        $string2 = /\\AD_Miner\-/ nocase ascii wide
        // Description: AD Miner is an Active Directory audit tool that leverages cypher queries to crunch data from the #Bloodhound graph database to uncover security weaknesses
        // Reference: https://github.com/Mazars-Tech/AD_Miner
        $string3 = /ad_miner\.sources\.modules\./ nocase ascii wide
        // Description: AD Miner is an Active Directory audit tool that leverages cypher queries to crunch data from the #Bloodhound graph database to uncover security weaknesses
        // Reference: https://github.com/Mazars-Tech/AD_Miner
        $string4 = /AD_Miner\-main/ nocase ascii wide
        // Description: AD Miner is an Active Directory audit tool that leverages cypher queries to crunch data from the #Bloodhound graph database to uncover security weaknesses
        // Reference: https://github.com/Mazars-Tech/AD_Miner
        $string5 = /AD\-miner\s\-/ nocase ascii wide
        // Description: AD Miner is an Active Directory audit tool that leverages cypher queries to crunch data from the #Bloodhound graph database to uncover security weaknesses
        // Reference: https://github.com/Mazars-Tech/AD_Miner
        $string6 = /https\:\/\/discord\.com\/invite\/5Hpj4Gs5SS/ nocase ascii wide
        // Description: AD Miner is an Active Directory audit tool that leverages cypher queries to crunch data from the #Bloodhound graph database to uncover security weaknesses
        // Reference: https://github.com/Mazars-Tech/AD_Miner
        $string7 = /Mazars\-Tech\/AD_Miner/ nocase ascii wide

    condition:
        any of them
}
