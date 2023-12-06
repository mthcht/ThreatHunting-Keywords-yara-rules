rule Scanners_Box
{
    meta:
        description = "Detection patterns for the tool 'Scanners-Box' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Scanners-Box"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Scanners Box also known as scanbox. is a powerful hacker toolkit. which has collected more than 10 categories of open source scanners from Github. including subdomain. database. middleware and other modular design scanner etc. But for other Well-known scanning tools. such as nmap. w3af. brakeman. arachni. nikto. metasploit. aircrack-ng will not be included in the scope of collection.
        // Reference: https://github.com/We5ter/Scanners-Box
        $string1 = /Scanners\-Box/ nocase ascii wide

    condition:
        any of them
}
