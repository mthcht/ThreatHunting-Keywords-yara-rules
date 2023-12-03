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
        $string1 = /.{0,1000}\/recon\-archy\.git.{0,1000}/ nocase ascii wide
        // Description: Linkedin Tools to reconstruct a company hierarchy from scraping relations and jobs title
        // Reference: https://github.com/shadawck/recon-archy
        $string2 = /.{0,1000}recon\-archy\sanalyse.{0,1000}/ nocase ascii wide
        // Description: Linkedin Tools to reconstruct a company hierarchy from scraping relations and jobs title
        // Reference: https://github.com/shadawck/recon-archy
        $string3 = /.{0,1000}recon\-archy\sbuild.{0,1000}/ nocase ascii wide
        // Description: Linkedin Tools to reconstruct a company hierarchy from scraping relations and jobs title
        // Reference: https://github.com/shadawck/recon-archy
        $string4 = /.{0,1000}recon\-archy\scrawl.{0,1000}/ nocase ascii wide
        // Description: Linkedin Tools to reconstruct a company hierarchy from scraping relations and jobs title
        // Reference: https://github.com/shadawck/recon-archy
        $string5 = /.{0,1000}recon\-archy\-master.{0,1000}/ nocase ascii wide
        // Description: Linkedin Tools to reconstruct a company hierarchy from scraping relations and jobs title
        // Reference: https://github.com/shadawck/recon-archy
        $string6 = /.{0,1000}remiflavien1\/recon\-archy.{0,1000}/ nocase ascii wide
        // Description: Linkedin Tools to reconstruct a company hierarchy from scraping relations and jobs title
        // Reference: https://github.com/shadawck/recon-archy
        $string7 = /.{0,1000}shadawck\/recon\-archy.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
