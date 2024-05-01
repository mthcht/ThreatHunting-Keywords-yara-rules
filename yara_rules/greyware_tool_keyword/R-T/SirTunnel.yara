rule SirTunnel
{
    meta:
        description = "Detection patterns for the tool 'SirTunnel' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SirTunnel"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: SirTunnel enables you to securely expose a webserver running on your computer to a public URL using HTTPS.
        // Reference: https://github.com/anderspitman/SirTunnel
        $string1 = /\s\$domain\ssirtunnel\s\$domain\s\$serverPort/ nocase ascii wide
        // Description: SirTunnel enables you to securely expose a webserver running on your computer to a public URL using HTTPS.
        // Reference: https://github.com/anderspitman/SirTunnel
        $string2 = /\ssirtunnel\.py/ nocase ascii wide
        // Description: SirTunnel enables you to securely expose a webserver running on your computer to a public URL using HTTPS.
        // Reference: https://github.com/anderspitman/SirTunnel
        $string3 = /\/config\/apps\/http\/servers\/sirtunnel\/routes/ nocase ascii wide
        // Description: SirTunnel enables you to securely expose a webserver running on your computer to a public URL using HTTPS.
        // Reference: https://github.com/anderspitman/SirTunnel
        $string4 = /\/SirTunnel\.git/ nocase ascii wide
        // Description: SirTunnel enables you to securely expose a webserver running on your computer to a public URL using HTTPS.
        // Reference: https://github.com/anderspitman/SirTunnel
        $string5 = /\/sirtunnel\.py/ nocase ascii wide
        // Description: SirTunnel enables you to securely expose a webserver running on your computer to a public URL using HTTPS.
        // Reference: https://github.com/anderspitman/SirTunnel
        $string6 = /\\sirtunnel\.py/ nocase ascii wide
        // Description: SirTunnel enables you to securely expose a webserver running on your computer to a public URL using HTTPS.
        // Reference: https://github.com/anderspitman/SirTunnel
        $string7 = /anderspitman\/SirTunnel/ nocase ascii wide
        // Description: SirTunnel enables you to securely expose a webserver running on your computer to a public URL using HTTPS.
        // Reference: https://github.com/anderspitman/SirTunnel
        $string8 = /d5687d84d518119cbdd84183bfe8cb29009d054794b3aed5bda7ad117a7e4d5e/ nocase ascii wide
        // Description: SirTunnel enables you to securely expose a webserver running on your computer to a public URL using HTTPS.
        // Reference: https://github.com/anderspitman/SirTunnel
        $string9 = /daps94\/SirTunnel/ nocase ascii wide
        // Description: SirTunnel enables you to securely expose a webserver running on your computer to a public URL using HTTPS.
        // Reference: https://github.com/anderspitman/SirTunnel
        $string10 = /http\:\/\/127\.0\.0\.1\:2019\/id\// nocase ascii wide
        // Description: SirTunnel enables you to securely expose a webserver running on your computer to a public URL using HTTPS.
        // Reference: https://github.com/anderspitman/SirTunnel
        $string11 = /matiboy\/SirTunnel/ nocase ascii wide

    condition:
        any of them
}
