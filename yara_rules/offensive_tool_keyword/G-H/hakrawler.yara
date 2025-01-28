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
        $string1 = "/bin/hakrawler"
        // Description: Simple fast web crawler designed for easy and quick discovery of endpoints and assets within a web application
        // Reference: https://github.com/hakluke/hakrawler
        $string2 = /\/hakrawler\.git/
        // Description: Simple fast web crawler designed for easy and quick discovery of endpoints and assets within a web application
        // Reference: https://github.com/hakluke/hakrawler
        $string3 = /\|\shakrawler/
        // Description: Simple fast web crawler designed for easy and quick discovery of endpoints and assets within a web application
        // Reference: https://github.com/hakluke/hakrawler
        $string4 = "hakluke/hakrawler"
        // Description: Simple fast web crawler designed for easy and quick discovery of endpoints and assets within a web application
        // Reference: https://github.com/hakluke/hakrawler
        $string5 = "hakrawler -"
        // Description: Simple fast web crawler designed for easy and quick discovery of endpoints and assets within a web application
        // Reference: https://github.com/hakluke/hakrawler
        $string6 = /hakrawler\.go/
        // Description: Simple fast web crawler designed for easy and quick discovery of endpoints and assets within a web application
        // Reference: https://github.com/hakluke/hakrawler
        $string7 = "hakrawler@latest"
        // Description: Simple fast web crawler designed for easy and quick discovery of endpoints and assets within a web application
        // Reference: https://github.com/hakluke/hakrawler
        $string8 = "hakrawler-master"
        // Description: Simple fast web crawler designed for easy and quick discovery of endpoints and assets within a web application
        // Reference: https://github.com/hakluke/hakrawler
        $string9 = "haktrails subdomains"
        // Description: Simple fast web crawler designed for easy and quick discovery of endpoints and assets within a web application
        // Reference: https://github.com/hakluke/hakrawler
        $string10 = "install hakrawler"

    condition:
        any of them
}
