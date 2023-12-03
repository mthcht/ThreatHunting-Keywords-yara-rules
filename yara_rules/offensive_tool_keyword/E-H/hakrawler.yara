rule hakrawler
{
    meta:
        description = "Detection patterns for the tool 'hakrawler' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "hakrawler"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Simple fast web crawler designed for easy and quick discovery of endpoints and assets within a web application
        // Reference: https://github.com/hakluke/hakrawler
        $string1 = /.{0,1000}\/bin\/hakrawler.{0,1000}/ nocase ascii wide
        // Description: Simple fast web crawler designed for easy and quick discovery of endpoints and assets within a web application
        // Reference: https://github.com/hakluke/hakrawler
        $string2 = /.{0,1000}\/hakrawler\.git.{0,1000}/ nocase ascii wide
        // Description: Simple fast web crawler designed for easy and quick discovery of endpoints and assets within a web application
        // Reference: https://github.com/hakluke/hakrawler
        $string3 = /.{0,1000}\|\shakrawler.{0,1000}/ nocase ascii wide
        // Description: Simple fast web crawler designed for easy and quick discovery of endpoints and assets within a web application
        // Reference: https://github.com/hakluke/hakrawler
        $string4 = /.{0,1000}hakluke\/hakrawler.{0,1000}/ nocase ascii wide
        // Description: Simple fast web crawler designed for easy and quick discovery of endpoints and assets within a web application
        // Reference: https://github.com/hakluke/hakrawler
        $string5 = /.{0,1000}hakrawler\s\-.{0,1000}/ nocase ascii wide
        // Description: Simple fast web crawler designed for easy and quick discovery of endpoints and assets within a web application
        // Reference: https://github.com/hakluke/hakrawler
        $string6 = /.{0,1000}hakrawler\.go.{0,1000}/ nocase ascii wide
        // Description: Simple fast web crawler designed for easy and quick discovery of endpoints and assets within a web application
        // Reference: https://github.com/hakluke/hakrawler
        $string7 = /.{0,1000}hakrawler\@latest.{0,1000}/ nocase ascii wide
        // Description: Simple fast web crawler designed for easy and quick discovery of endpoints and assets within a web application
        // Reference: https://github.com/hakluke/hakrawler
        $string8 = /.{0,1000}hakrawler\-master.{0,1000}/ nocase ascii wide
        // Description: Simple fast web crawler designed for easy and quick discovery of endpoints and assets within a web application
        // Reference: https://github.com/hakluke/hakrawler
        $string9 = /.{0,1000}haktrails\ssubdomains.{0,1000}/ nocase ascii wide
        // Description: Simple fast web crawler designed for easy and quick discovery of endpoints and assets within a web application
        // Reference: https://github.com/hakluke/hakrawler
        $string10 = /.{0,1000}install\shakrawler.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
