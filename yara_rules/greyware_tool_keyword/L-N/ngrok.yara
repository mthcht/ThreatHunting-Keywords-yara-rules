rule ngrok
{
    meta:
        description = "Detection patterns for the tool 'ngrok' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ngrok"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: ngrok - abused by attackers for C2 usage
        // Reference: https://github.com/inconshreveable/ngrok
        $string1 = /\.ngrok\.me/ nocase ascii wide
        // Description: ngrok - abused by attackers for C2 usage
        // Reference: https://github.com/RoseSecurity/Red-Teaming-TTPs/blob/main/Linux.md
        $string2 = /\/ngrok\.exe/ nocase ascii wide
        // Description: ngrok - abused by attackers for C2 usage
        // Reference: https://github.com/inconshreveable/ngrok
        $string3 = /\/ngrok\.git/ nocase ascii wide
        // Description: ngrok - abused by attackers for C2 usage
        // Reference: https://github.com/inconshreveable/ngrok
        $string4 = /\/ngrok\.go/ nocase ascii wide
        // Description: ngrok - abused by attackers for C2 usage
        // Reference: https://github.com/inconshreveable/ngrok
        $string5 = /\/ngrok\.log/
        // Description: ngrok - abused by attackers for C2 usage
        // Reference: https://github.com/inconshreveable/ngrok
        $string6 = /\/ngrokd\.go/ nocase ascii wide
        // Description: ngrok - abused by attackers for C2 usage
        // Reference: https://github.com/inconshreveable/ngrok
        $string7 = /\/ngrokroot\.crt/
        // Description: ngrok - abused by attackers for C2 usage
        // Reference: https://github.com/RoseSecurity/Red-Teaming-TTPs/blob/main/Linux.md
        $string8 = /\\ngrok\.exe/ nocase ascii wide
        // Description: ngrok - abused by attackers for C2 usage
        // Reference: https://github.com/inconshreveable/ngrok
        $string9 = /\\ngrok\.go/ nocase ascii wide
        // Description: ngrok - abused by attackers for C2 usage
        // Reference: https://github.com/inconshreveable/ngrok
        $string10 = /\\ngrok\.log/ nocase ascii wide
        // Description: ngrok - abused by attackers for C2 usage
        // Reference: https://github.com/inconshreveable/ngrok
        $string11 = /\\ngrok\\config\.yml/ nocase ascii wide
        // Description: ngrok - abused by attackers for C2 usage
        // Reference: https://github.com/inconshreveable/ngrok
        $string12 = /\\ngrok\\ng\.psm1/ nocase ascii wide
        // Description: ngrok - abused by attackers for C2 usage
        // Reference: https://github.com/inconshreveable/ngrok
        $string13 = /\\ngrokd\.go/ nocase ascii wide
        // Description: ngrok - abused by attackers for C2 usage
        // Reference: https://github.com/inconshreveable/ngrok
        $string14 = "6abfc342f0a659066c8b42999510ccc3592b499569c2e7af37470a445a2e3560" nocase ascii wide
        // Description: ngrok - abused by attackers for C2 usage
        // Reference: https://github.com/inconshreveable/ngrok
        $string15 = "fe9dd722a085bce94fe2403f8d02e20becf0f0faa019d0789fadf35b66611a46" nocase ascii wide
        // Description: ngrok - abused by attackers for C2 usage
        // Reference: https://github.com/RoseSecurity/Red-Teaming-TTPs/blob/main/Linux.md
        $string16 = /http\:\/\/.{0,1000}\.ngrok\.io/ nocase ascii wide
        // Description: ngrok - abused by attackers for C2 usage
        // Reference: https://github.com/inconshreveable/ngrok
        $string17 = /http\:\/\/127\.0\.0\.1\:4040\/api\/tunnels/ nocase ascii wide
        // Description: ngrok - abused by attackers for C2 usage
        // Reference: https://github.com/RoseSecurity/Red-Teaming-TTPs/blob/main/Linux.md
        $string18 = /https\:\/\/.{0,1000}\.ngrok\.io/ nocase ascii wide
        // Description: ngrok - abused by attackers for C2 usage
        // Reference: https://github.com/inconshreveable/ngrok
        $string19 = "inconshreveable/ngrok" nocase ascii wide
        // Description: ngrok - abused by attackers for C2 usage
        // Reference: https://github.com/RoseSecurity/Red-Teaming-TTPs/blob/main/Linux.md
        $string20 = /LHOST\=0\.tcp\.ngrok\.io/ nocase ascii wide
        // Description: ngrok - abused by attackers for C2 usage
        // Reference: https://github.com/inconshreveable/ngrok
        $string21 = /Mozilla\/5\.0\s\(compatible\;\sngrok\)/ nocase ascii wide
        // Description: ngrok - abused by attackers for C2 usage
        // Reference: https://github.com/RoseSecurity/Red-Teaming-TTPs/blob/main/Linux.md
        $string22 = "ngrok tcp " nocase ascii wide
        // Description: ngrok - abused by attackers for C2 usage
        // Reference: https://github.com/inconshreveable/ngrok
        $string23 = /ngrok\,\sInc\./ nocase ascii wide
        // Description: ngrok - abused by attackers for C2 usage
        // Reference: https://github.com/inconshreveable/ngrok
        $string24 = /ngrokd\.ngrok\.com/ nocase ascii wide
        // Description: ngrok - abused by attackers for C2 usage
        // Reference: https://github.com/RoseSecurity/Red-Teaming-TTPs/blob/main/Linux.md
        $string25 = /tcp\:\/\/0\.tcp\.ngrok\.io\:/ nocase ascii wide
        // Description: ngrok - abused by attackers for C2 usage
        // Reference: https://github.com/inconshreveable/ngrok
        $string26 = /tunnel\.ap\.ngrok\.com/ nocase ascii wide
        // Description: ngrok - abused by attackers for C2 usage
        // Reference: https://github.com/inconshreveable/ngrok
        $string27 = /tunnel\.au\.ngrok\.com/ nocase ascii wide
        // Description: ngrok - abused by attackers for C2 usage
        // Reference: https://github.com/inconshreveable/ngrok
        $string28 = /tunnel\.eu\.ngrok\.com/ nocase ascii wide
        // Description: ngrok - abused by attackers for C2 usage
        // Reference: https://github.com/inconshreveable/ngrok
        $string29 = /tunnel\.in\.ngrok\.com/ nocase ascii wide
        // Description: ngrok - abused by attackers for C2 usage
        // Reference: https://github.com/inconshreveable/ngrok
        $string30 = /tunnel\.jp\.ngrok\.com/ nocase ascii wide
        // Description: ngrok - abused by attackers for C2 usage
        // Reference: https://github.com/inconshreveable/ngrok
        $string31 = /tunnel\.sa\.ngrok\.com/ nocase ascii wide
        // Description: ngrok - abused by attackers for C2 usage
        // Reference: https://github.com/inconshreveable/ngrok
        $string32 = /tunnel\.us\.ngrok\.com/ nocase ascii wide

    condition:
        any of them
}
