rule Lastenzug
{
    meta:
        description = "Detection patterns for the tool 'Lastenzug' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Lastenzug"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Socka4a proxy based on websockets
        // Reference: https://github.com/codewhitesec/Lastenzug
        $string1 = "! This is a sample loader for Lastenzug" nocase ascii wide
        // Description: Socka4a proxy based on websockets
        // Reference: https://github.com/codewhitesec/Lastenzug
        $string2 = /\/LastenLoader\.exe/ nocase ascii wide
        // Description: Socka4a proxy based on websockets
        // Reference: https://github.com/codewhitesec/Lastenzug
        $string3 = /\/Lastenzug\.git/ nocase ascii wide
        // Description: Socka4a proxy based on websockets
        // Reference: https://github.com/codewhitesec/Lastenzug
        $string4 = /\\LastenLoader\.exe/ nocase ascii wide
        // Description: Socka4a proxy based on websockets
        // Reference: https://github.com/codewhitesec/Lastenzug
        $string5 = /127\.0\.0\.1\:1337/ nocase ascii wide
        // Description: Socka4a proxy based on websockets
        // Reference: https://github.com/codewhitesec/Lastenzug
        $string6 = "a07f5f82857dd9e0b02b4bb90783e028ff42e80fe8286dd2c8e983db138c3820" nocase ascii wide
        // Description: Socka4a proxy based on websockets
        // Reference: https://github.com/codewhitesec/Lastenzug
        $string7 = /bin\/LastenPIC\.bin/ nocase ascii wide
        // Description: Socka4a proxy based on websockets
        // Reference: https://github.com/codewhitesec/Lastenzug
        $string8 = "build -o LastenServer"
        // Description: Socka4a proxy based on websockets
        // Reference: https://github.com/codewhitesec/Lastenzug
        $string9 = "codewhitesec/Lastenzug" nocase ascii wide
        // Description: Socka4a proxy based on websockets
        // Reference: https://github.com/codewhitesec/Lastenzug
        $string10 = "d2807b9860e0e4801cd00f45421b5bcab30c1a818f193e4a3d33be8f65c99ea0" nocase ascii wide
        // Description: Socka4a proxy based on websockets
        // Reference: https://github.com/codewhitesec/Lastenzug
        $string11 = "LastenPIC/SpiderPIC" nocase ascii wide
        // Description: Socka4a proxy based on websockets
        // Reference: https://github.com/codewhitesec/Lastenzug
        $string12 = "LastenServer server "
        // Description: Socka4a proxy based on websockets
        // Reference: https://github.com/codewhitesec/Lastenzug
        $string13 = "Lastenzug - PIC Socks4a proxy by @invist" nocase ascii wide
        // Description: Socka4a proxy based on websockets
        // Reference: https://github.com/codewhitesec/Lastenzug
        $string14 = /ws\:\/\/127\.0\.0\.1\:1339\/yolo/ nocase ascii wide

    condition:
        any of them
}
