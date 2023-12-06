rule recon_archy
{
    meta:
        description = "Detection patterns for the tool 'recon-archy' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "recon-archy"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Linkedin Tools to reconstruct a company hierarchy from scraping relations and jobs title
        // Reference: https://github.com/shadawck/recon-archy
        $string1 = /\/recon\-archy\.git/ nocase ascii wide
        // Description: Linkedin Tools to reconstruct a company hierarchy from scraping relations and jobs title
        // Reference: https://github.com/shadawck/recon-archy
        $string2 = /recon\-archy\sanalyse/ nocase ascii wide
        // Description: Linkedin Tools to reconstruct a company hierarchy from scraping relations and jobs title
        // Reference: https://github.com/shadawck/recon-archy
        $string3 = /recon\-archy\sbuild/ nocase ascii wide
        // Description: Linkedin Tools to reconstruct a company hierarchy from scraping relations and jobs title
        // Reference: https://github.com/shadawck/recon-archy
        $string4 = /recon\-archy\scrawl/ nocase ascii wide
        // Description: Linkedin Tools to reconstruct a company hierarchy from scraping relations and jobs title
        // Reference: https://github.com/shadawck/recon-archy
        $string5 = /recon\-archy\-master/ nocase ascii wide
        // Description: Linkedin Tools to reconstruct a company hierarchy from scraping relations and jobs title
        // Reference: https://github.com/shadawck/recon-archy
        $string6 = /remiflavien1\/recon\-archy/ nocase ascii wide
        // Description: Linkedin Tools to reconstruct a company hierarchy from scraping relations and jobs title
        // Reference: https://github.com/shadawck/recon-archy
        $string7 = /shadawck\/recon\-archy/ nocase ascii wide

    condition:
        any of them
}
