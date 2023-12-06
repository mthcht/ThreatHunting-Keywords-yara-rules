rule Synergy_httpx
{
    meta:
        description = "Detection patterns for the tool 'Synergy-httpx' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Synergy-httpx"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A Python http(s) server designed to assist in red teaming activities such as receiving intercepted data via POST requests and serving content dynamically
        // Reference: https://github.com/t3l3machus/Synergy-httpx
        $string1 = /\/Synergy\-httpx\.git/ nocase ascii wide
        // Description: A Python http(s) server designed to assist in red teaming activities such as receiving intercepted data via POST requests and serving content dynamically
        // Reference: https://github.com/t3l3machus/Synergy-httpx
        $string2 = /curl\s\-\-connect\-timeout\s3\.14\s\-s\sifconfig\.me/ nocase ascii wide
        // Description: A Python http(s) server designed to assist in red teaming activities such as receiving intercepted data via POST requests and serving content dynamically
        // Reference: https://github.com/t3l3machus/Synergy-httpx
        $string3 = /synergy_httpx\.py/ nocase ascii wide
        // Description: A Python http(s) server designed to assist in red teaming activities such as receiving intercepted data via POST requests and serving content dynamically
        // Reference: https://github.com/t3l3machus/Synergy-httpx
        $string4 = /Synergy\-httpx\-main/ nocase ascii wide
        // Description: A Python http(s) server designed to assist in red teaming activities such as receiving intercepted data via POST requests and serving content dynamically
        // Reference: https://github.com/t3l3machus/Synergy-httpx
        $string5 = /t3l3machus\/Synergy\-httpx/ nocase ascii wide

    condition:
        any of them
}
