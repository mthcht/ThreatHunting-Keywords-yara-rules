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
        $string5 = /\/ngrok\.log/ nocase ascii wide
        // Description: ngrok - abused by attackers for C2 usage
        // Reference: https://github.com/inconshreveable/ngrok
        $string6 = /\/ngrokd\.go/ nocase ascii wide
        // Description: ngrok - abused by attackers for C2 usage
        // Reference: https://github.com/inconshreveable/ngrok
        $string7 = /\/ngrokroot\.crt/ nocase ascii wide
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
        $string11 = /\\ngrokd\.go/ nocase ascii wide
        // Description: ngrok - abused by attackers for C2 usage
        // Reference: https://github.com/inconshreveable/ngrok
        $string12 = /6abfc342f0a659066c8b42999510ccc3592b499569c2e7af37470a445a2e3560/ nocase ascii wide
        // Description: ngrok - abused by attackers for C2 usage
        // Reference: https://github.com/inconshreveable/ngrok
        $string13 = /fe9dd722a085bce94fe2403f8d02e20becf0f0faa019d0789fadf35b66611a46/ nocase ascii wide
        // Description: ngrok - abused by attackers for C2 usage
        // Reference: https://github.com/RoseSecurity/Red-Teaming-TTPs/blob/main/Linux.md
        $string14 = /http\:\/\/.{0,1000}\.ngrok\.io/ nocase ascii wide
        // Description: ngrok - abused by attackers for C2 usage
        // Reference: https://github.com/RoseSecurity/Red-Teaming-TTPs/blob/main/Linux.md
        $string15 = /https\:\/\/.{0,1000}\.ngrok\.io/ nocase ascii wide
        // Description: ngrok - abused by attackers for C2 usage
        // Reference: https://github.com/inconshreveable/ngrok
        $string16 = /inconshreveable\/ngrok/ nocase ascii wide
        // Description: ngrok - abused by attackers for C2 usage
        // Reference: https://github.com/RoseSecurity/Red-Teaming-TTPs/blob/main/Linux.md
        $string17 = /LHOST\=0\.tcp\.ngrok\.io/ nocase ascii wide
        // Description: ngrok - abused by attackers for C2 usage
        // Reference: https://github.com/inconshreveable/ngrok
        $string18 = /Mozilla\/5\.0\s\(compatible\;\sngrok\)/ nocase ascii wide
        // Description: ngrok - abused by attackers for C2 usage
        // Reference: https://github.com/RoseSecurity/Red-Teaming-TTPs/blob/main/Linux.md
        $string19 = /ngrok\stcp\s/ nocase ascii wide
        // Description: ngrok - abused by attackers for C2 usage
        // Reference: https://github.com/inconshreveable/ngrok
        $string20 = /ngrokd\.ngrok\.com/ nocase ascii wide
        // Description: ngrok - abused by attackers for C2 usage
        // Reference: https://github.com/RoseSecurity/Red-Teaming-TTPs/blob/main/Linux.md
        $string21 = /tcp\:\/\/0\.tcp\.ngrok\.io\:/ nocase ascii wide
        // Description: ngrok - abused by attackers for C2 usage
        // Reference: https://github.com/inconshreveable/ngrok
        $string22 = /tunnel\.ap\.ngrok\.com/ nocase ascii wide
        // Description: ngrok - abused by attackers for C2 usage
        // Reference: https://github.com/inconshreveable/ngrok
        $string23 = /tunnel\.au\.ngrok\.com/ nocase ascii wide
        // Description: ngrok - abused by attackers for C2 usage
        // Reference: https://github.com/inconshreveable/ngrok
        $string24 = /tunnel\.eu\.ngrok\.com/ nocase ascii wide
        // Description: ngrok - abused by attackers for C2 usage
        // Reference: https://github.com/inconshreveable/ngrok
        $string25 = /tunnel\.in\.ngrok\.com/ nocase ascii wide
        // Description: ngrok - abused by attackers for C2 usage
        // Reference: https://github.com/inconshreveable/ngrok
        $string26 = /tunnel\.jp\.ngrok\.com/ nocase ascii wide
        // Description: ngrok - abused by attackers for C2 usage
        // Reference: https://github.com/inconshreveable/ngrok
        $string27 = /tunnel\.sa\.ngrok\.com/ nocase ascii wide
        // Description: ngrok - abused by attackers for C2 usage
        // Reference: https://github.com/inconshreveable/ngrok
        $string28 = /tunnel\.us\.ngrok\.com/ nocase ascii wide

    condition:
        any of them
}
