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
        $string1 = /\/bin\/hakrawler/ nocase ascii wide
        // Description: Simple fast web crawler designed for easy and quick discovery of endpoints and assets within a web application
        // Reference: https://github.com/hakluke/hakrawler
        $string2 = /\/hakrawler\.git/ nocase ascii wide
        // Description: Simple fast web crawler designed for easy and quick discovery of endpoints and assets within a web application
        // Reference: https://github.com/hakluke/hakrawler
        $string3 = /\|\shakrawler/ nocase ascii wide
        // Description: Simple fast web crawler designed for easy and quick discovery of endpoints and assets within a web application
        // Reference: https://github.com/hakluke/hakrawler
        $string4 = /hakluke\/hakrawler/ nocase ascii wide
        // Description: Simple fast web crawler designed for easy and quick discovery of endpoints and assets within a web application
        // Reference: https://github.com/hakluke/hakrawler
        $string5 = /hakrawler\s\-/ nocase ascii wide
        // Description: Simple fast web crawler designed for easy and quick discovery of endpoints and assets within a web application
        // Reference: https://github.com/hakluke/hakrawler
        $string6 = /hakrawler\.go/ nocase ascii wide
        // Description: Simple fast web crawler designed for easy and quick discovery of endpoints and assets within a web application
        // Reference: https://github.com/hakluke/hakrawler
        $string7 = /hakrawler\@latest/ nocase ascii wide
        // Description: Simple fast web crawler designed for easy and quick discovery of endpoints and assets within a web application
        // Reference: https://github.com/hakluke/hakrawler
        $string8 = /hakrawler\-master/ nocase ascii wide
        // Description: Simple fast web crawler designed for easy and quick discovery of endpoints and assets within a web application
        // Reference: https://github.com/hakluke/hakrawler
        $string9 = /haktrails\ssubdomains/ nocase ascii wide
        // Description: Simple fast web crawler designed for easy and quick discovery of endpoints and assets within a web application
        // Reference: https://github.com/hakluke/hakrawler
        $string10 = /install\shakrawler/ nocase ascii wide

    condition:
        any of them
}
