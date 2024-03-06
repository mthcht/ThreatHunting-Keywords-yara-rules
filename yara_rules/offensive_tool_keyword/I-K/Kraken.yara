rule Kraken
{
    meta:
        description = "Detection patterns for the tool 'Kraken' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Kraken"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Kraken is a modular multi-language webshell focused on web post-exploitation and defense evasion.
        // Reference: https://github.com/kraken-ng/Kraken
        $string1 = /\.py\s\-c\s\-m\sc2\s\-p\sutils/ nocase ascii wide
        // Description: Kraken is a modular multi-language webshell focused on web post-exploitation and defense evasion.
        // Reference: https://github.com/kraken-ng/Kraken
        $string2 = /conda\sactivate\skraken/ nocase ascii wide
        // Description: Kraken is a modular multi-language webshell focused on web post-exploitation and defense evasion.
        // Reference: https://github.com/kraken-ng/Kraken
        $string3 = /conda\screate\s\-n\skraken\spython\=/ nocase ascii wide
        // Description: Kraken is a modular multi-language webshell focused on web post-exploitation and defense evasion.
        // Reference: https://github.com/kraken-ng/Kraken
        $string4 = /from\slib\.config\simport\s.{0,1000}C2_COMMANDS/ nocase ascii wide
        // Description: Kraken is a modular multi-language webshell focused on web post-exploitation and defense evasion.
        // Reference: https://github.com/kraken-ng/Kraken
        $string5 = /Kraken\-1\.2\.0\.zip/ nocase ascii wide
        // Description: Kraken is a modular multi-language webshell focused on web post-exploitation and defense evasion.
        // Reference: https://github.com/kraken-ng/Kraken
        $string6 = /kraken\-ng\/Kraken/ nocase ascii wide
        // Description: Kraken is a modular multi-language webshell focused on web post-exploitation and defense evasion.
        // Reference: https://github.com/kraken-ng/Kraken
        $string7 = /python\skraken\.py\s\-/ nocase ascii wide

    condition:
        any of them
}
