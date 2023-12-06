rule jackdaw
{
    meta:
        description = "Detection patterns for the tool 'jackdaw' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "jackdaw"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Jackdaw is here to collect all information in your domain. store it in a SQL database and show you nice graphs on how your domain objects interact with each-other an how a potential attacker may exploit these interactions. It also comes with a handy feature to help you in a password-cracking project by storing/looking up/reporting hashes/passowrds/users.
        // Reference: https://github.com/skelsec/jackdaw
        $string1 = /\/well_known_sids\.py/ nocase ascii wide
        // Description: Jackdaw is here to collect all information in your domain. store it in a SQL database and show you nice graphs on how your domain objects interact with each-other an how a potential attacker may exploit these interactions. It also comes with a handy feature to help you in a password-cracking project by storing/looking up/reporting hashes/passowrds/users.
        // Reference: https://github.com/skelsec/jackdaw
        $string2 = /gatherer\/gatherer\.py/ nocase ascii wide
        // Description: Jackdaw is here to collect all information in your domain. store it in a SQL database and show you nice graphs on how your domain objects interact with each-other an how a potential attacker may exploit these interactions. It also comes with a handy feature to help you in a password-cracking project by storing/looking up/reporting hashes/passowrds/users.
        // Reference: https://github.com/skelsec/jackdaw
        $string3 = /jackdaw\s\-\-/ nocase ascii wide
        // Description: Jackdaw is here to collect all information in your domain. store it in a SQL database and show you nice graphs on how your domain objects interact with each-other an how a potential attacker may exploit these interactions. It also comes with a handy feature to help you in a password-cracking project by storing/looking up/reporting hashes/passowrds/users.
        // Reference: https://github.com/skelsec/jackdaw
        $string4 = /jackdaw\.py/ nocase ascii wide
        // Description: Jackdaw is here to collect all information in your domain. store it in a SQL database and show you nice graphs on how your domain objects interact with each-other an how a potential attacker may exploit these interactions. It also comes with a handy feature to help you in a password-cracking project by storing/looking up/reporting hashes/passowrds/users.
        // Reference: https://github.com/skelsec/jackdaw
        $string5 = /skelsec\/jackdaw/ nocase ascii wide

    condition:
        any of them
}
