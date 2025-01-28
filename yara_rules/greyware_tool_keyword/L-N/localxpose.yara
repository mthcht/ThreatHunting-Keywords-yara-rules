rule localxpose
{
    meta:
        description = "Detection patterns for the tool 'localxpose' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "localxpose"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: LocalXpose is a reverse proxy that enables you to expose your localhost to the internet
        // Reference: https://localxpose.io/
        $string1 = /\.loclx\.io\:/ nocase ascii wide
        // Description: LocalXpose is a reverse proxy that enables you to expose your localhost to the internet
        // Reference: https://localxpose.io/
        $string2 = /\/.{0,1000}\.loclx\.io/ nocase ascii wide
        // Description: LocalXpose is a reverse proxy that enables you to expose your localhost to the internet
        // Reference: https://localxpose.io/
        $string3 = /\/loclx\.exe/ nocase ascii wide
        // Description: LocalXpose is a reverse proxy that enables you to expose your localhost to the internet
        // Reference: https://localxpose.io/
        $string4 = /\/loclx\-windows\-amd64\.zip/ nocase ascii wide
        // Description: LocalXpose is a reverse proxy that enables you to expose your localhost to the internet
        // Reference: https://localxpose.io/
        $string5 = /\\loclx\.exe/ nocase ascii wide
        // Description: LocalXpose is a reverse proxy that enables you to expose your localhost to the internet
        // Reference: https://localxpose.io/
        $string6 = /\\loclx\-windows\-amd64\.zip/ nocase ascii wide
        // Description: LocalXpose is a reverse proxy that enables you to expose your localhost to the internet
        // Reference: https://localxpose.io/
        $string7 = "17a9356024d2fa2ae8f327fc5babc10eb859e0c433e768cd03a50dd9c7880601" nocase ascii wide
        // Description: LocalXpose is a reverse proxy that enables you to expose your localhost to the internet
        // Reference: https://localxpose.io/
        $string8 = "33ab2fa30777211450e30c21c45803cdf076cb991f05691bd60aef97a8183e04" nocase ascii wide
        // Description: LocalXpose is a reverse proxy that enables you to expose your localhost to the internet
        // Reference: https://localxpose.io/
        $string9 = /api\.localxpose\.io/ nocase ascii wide
        // Description: LocalXpose is a reverse proxy that enables you to expose your localhost to the internet
        // Reference: https://localxpose.io/
        $string10 = "brew install --cask localxpose" nocase ascii wide
        // Description: LocalXpose is a reverse proxy that enables you to expose your localhost to the internet
        // Reference: https://localxpose.io/
        $string11 = "cd1978742a4afdbaaa15bf712d5c90bef4144caa99024df98f6a9ad58043ae85" nocase ascii wide
        // Description: LocalXpose is a reverse proxy that enables you to expose your localhost to the internet
        // Reference: https://localxpose.io/
        $string12 = "choco install localxpose" nocase ascii wide
        // Description: LocalXpose is a reverse proxy that enables you to expose your localhost to the internet
        // Reference: https://localxpose.io/
        $string13 = /https\:\/\/localxpose\.io\/download/ nocase ascii wide
        // Description: LocalXpose is a reverse proxy that enables you to expose your localhost to the internet
        // Reference: https://localxpose.io/
        $string14 = "localxpose/localxpose" nocase ascii wide
        // Description: LocalXpose is a reverse proxy that enables you to expose your localhost to the internet
        // Reference: https://localxpose.io/
        $string15 = "loclx tunnel config " nocase ascii wide
        // Description: LocalXpose is a reverse proxy that enables you to expose your localhost to the internet
        // Reference: https://localxpose.io/
        $string16 = "loclx tunnel http " nocase ascii wide
        // Description: LocalXpose is a reverse proxy that enables you to expose your localhost to the internet
        // Reference: https://localxpose.io/
        $string17 = "loclx tunnel tcp " nocase ascii wide
        // Description: LocalXpose is a reverse proxy that enables you to expose your localhost to the internet
        // Reference: https://localxpose.io/
        $string18 = "loclx tunnel tls " nocase ascii wide
        // Description: LocalXpose is a reverse proxy that enables you to expose your localhost to the internet
        // Reference: https://localxpose.io/
        $string19 = "loclx tunnel udp " nocase ascii wide
        // Description: LocalXpose is a reverse proxy that enables you to expose your localhost to the internet
        // Reference: https://localxpose.io/
        $string20 = /loclx\.exe\stunnel\shttp\s/ nocase ascii wide
        // Description: LocalXpose is a reverse proxy that enables you to expose your localhost to the internet
        // Reference: https://localxpose.io/
        $string21 = /loclx\.exe\stunnel\stcp\s/ nocase ascii wide
        // Description: LocalXpose is a reverse proxy that enables you to expose your localhost to the internet
        // Reference: https://localxpose.io/
        $string22 = /loclx\.exe\stunnel\stls\s/ nocase ascii wide
        // Description: LocalXpose is a reverse proxy that enables you to expose your localhost to the internet
        // Reference: https://localxpose.io/
        $string23 = /loclx\.exe\stunnel\sudp\s/ nocase ascii wide
        // Description: LocalXpose is a reverse proxy that enables you to expose your localhost to the internet
        // Reference: https://localxpose.io/
        $string24 = /loclx\-client\.s3\.amazonaws\.com/ nocase ascii wide
        // Description: LocalXpose is a reverse proxy that enables you to expose your localhost to the internet
        // Reference: https://localxpose.io/
        $string25 = "npm install localxpose" nocase ascii wide
        // Description: LocalXpose is a reverse proxy that enables you to expose your localhost to the internet
        // Reference: https://localxpose.io/
        $string26 = "snap install localxpose" nocase ascii wide
        // Description: LocalXpose is a reverse proxy that enables you to expose your localhost to the internet
        // Reference: https://localxpose.io/
        $string27 = "yarn add localxpose" nocase ascii wide

    condition:
        any of them
}
