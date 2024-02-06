rule Neo4j
{
    meta:
        description = "Detection patterns for the tool 'Neo4j' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Neo4j"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Neo4j queries - Computers in Unconstrained Delegations
        // Reference: https://hideandsec.sh/books/cheatsheets-82c/page/active-directory
        $string1 = /MATCH\s\(c\:Computer\s\{unconsraineddelegation\:true\}\)\sRETURN\sc/ nocase ascii wide
        // Description: Neo4j queries - Computers AllowedToDelegate to other computers
        // Reference: https://hideandsec.sh/books/cheatsheets-82c/page/active-directory
        $string2 = /MATCH\s\(c\:Computer\).{0,1000}\(t\:Computer\).{0,1000}\s.{0,1000}\-\[\:AllowedToDelegate\].{0,1000}\sreturn\sp/ nocase ascii wide
        // Description: Neo4j queries - Potential SQL Admins
        // Reference: https://hideandsec.sh/books/cheatsheets-82c/page/active-directory
        $string3 = /MATCH\sp\=\(u\:User\)\-\[\:SQLAdmin\].{0,1000}\(c\:Computer\)\sreturn\sp/ nocase ascii wide
        // Description: Neo4j queries - Computers AllowedToDelegate to other computers
        // Reference: https://hideandsec.sh/books/cheatsheets-82c/page/active-directory
        $string4 = /neo4j\sstart/ nocase ascii wide

    condition:
        any of them
}
