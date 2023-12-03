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
        $string1 = /.{0,1000}\/AD_Miner\.git.{0,1000}/ nocase ascii wide
        // Description: AD Miner is an Active Directory audit tool that leverages cypher queries to crunch data from the #Bloodhound graph database to uncover security weaknesses
        // Reference: https://github.com/Mazars-Tech/AD_Miner
        $string2 = /.{0,1000}\\AD_Miner\-.{0,1000}/ nocase ascii wide
        // Description: AD Miner is an Active Directory audit tool that leverages cypher queries to crunch data from the #Bloodhound graph database to uncover security weaknesses
        // Reference: https://github.com/Mazars-Tech/AD_Miner
        $string3 = /.{0,1000}ad_miner\.sources\.modules\..{0,1000}/ nocase ascii wide
        // Description: AD Miner is an Active Directory audit tool that leverages cypher queries to crunch data from the #Bloodhound graph database to uncover security weaknesses
        // Reference: https://github.com/Mazars-Tech/AD_Miner
        $string4 = /.{0,1000}AD_Miner\-main.{0,1000}/ nocase ascii wide
        // Description: AD Miner is an Active Directory audit tool that leverages cypher queries to crunch data from the #Bloodhound graph database to uncover security weaknesses
        // Reference: https://github.com/Mazars-Tech/AD_Miner
        $string5 = /.{0,1000}AD\-miner\s\-.{0,1000}/ nocase ascii wide
        // Description: AD Miner is an Active Directory audit tool that leverages cypher queries to crunch data from the #Bloodhound graph database to uncover security weaknesses
        // Reference: https://github.com/Mazars-Tech/AD_Miner
        $string6 = /.{0,1000}https:\/\/discord\.com\/invite\/5Hpj4Gs5SS.{0,1000}/ nocase ascii wide
        // Description: AD Miner is an Active Directory audit tool that leverages cypher queries to crunch data from the #Bloodhound graph database to uncover security weaknesses
        // Reference: https://github.com/Mazars-Tech/AD_Miner
        $string7 = /.{0,1000}Mazars\-Tech\/AD_Miner.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
