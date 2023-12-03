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
        $string1 = /.{0,1000}\/well_known_sids\.py.{0,1000}/ nocase ascii wide
        // Description: Jackdaw is here to collect all information in your domain. store it in a SQL database and show you nice graphs on how your domain objects interact with each-other an how a potential attacker may exploit these interactions. It also comes with a handy feature to help you in a password-cracking project by storing/looking up/reporting hashes/passowrds/users.
        // Reference: https://github.com/skelsec/jackdaw
        $string2 = /.{0,1000}gatherer\/gatherer\.py.{0,1000}/ nocase ascii wide
        // Description: Jackdaw is here to collect all information in your domain. store it in a SQL database and show you nice graphs on how your domain objects interact with each-other an how a potential attacker may exploit these interactions. It also comes with a handy feature to help you in a password-cracking project by storing/looking up/reporting hashes/passowrds/users.
        // Reference: https://github.com/skelsec/jackdaw
        $string3 = /.{0,1000}jackdaw\s\-\-.{0,1000}/ nocase ascii wide
        // Description: Jackdaw is here to collect all information in your domain. store it in a SQL database and show you nice graphs on how your domain objects interact with each-other an how a potential attacker may exploit these interactions. It also comes with a handy feature to help you in a password-cracking project by storing/looking up/reporting hashes/passowrds/users.
        // Reference: https://github.com/skelsec/jackdaw
        $string4 = /.{0,1000}jackdaw\.py.{0,1000}/ nocase ascii wide
        // Description: Jackdaw is here to collect all information in your domain. store it in a SQL database and show you nice graphs on how your domain objects interact with each-other an how a potential attacker may exploit these interactions. It also comes with a handy feature to help you in a password-cracking project by storing/looking up/reporting hashes/passowrds/users.
        // Reference: https://github.com/skelsec/jackdaw
        $string5 = /.{0,1000}skelsec\/jackdaw.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
