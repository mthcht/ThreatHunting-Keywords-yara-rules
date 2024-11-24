rule SniffPass
{
    meta:
        description = "Detection patterns for the tool 'SniffPass' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SniffPass"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: password monitoring software that listens to your network - capture the passwords that pass through your network adapter and display them on the screen instantly
        // Reference: https://www.nirsoft.net/utils/password_sniffer.html
        $string1 = /\/password_sniffer\.html/ nocase ascii wide
        // Description: password monitoring software that listens to your network - capture the passwords that pass through your network adapter and display them on the screen instantly
        // Reference: https://www.nirsoft.net/utils/password_sniffer.html
        $string2 = "/sniffpass-x64" nocase ascii wide
        // Description: password monitoring software that listens to your network - capture the passwords that pass through your network adapter and display them on the screen instantly
        // Reference: https://www.nirsoft.net/utils/password_sniffer.html
        $string3 = /\\SniffPass\.chm/ nocase ascii wide
        // Description: password monitoring software that listens to your network - capture the passwords that pass through your network adapter and display them on the screen instantly
        // Reference: https://www.nirsoft.net/utils/password_sniffer.html
        $string4 = /\\SniffPass\.pdb/ nocase ascii wide
        // Description: password monitoring software that listens to your network - capture the passwords that pass through your network adapter and display them on the screen instantly
        // Reference: https://www.nirsoft.net/utils/password_sniffer.html
        $string5 = /\\sniffpass\-x64/ nocase ascii wide
        // Description: password monitoring software that listens to your network - capture the passwords that pass through your network adapter and display them on the screen instantly
        // Reference: https://www.nirsoft.net/utils/password_sniffer.html
        $string6 = ">Password Sniffer<" nocase ascii wide
        // Description: password monitoring software that listens to your network - capture the passwords that pass through your network adapter and display them on the screen instantly
        // Reference: https://www.nirsoft.net/utils/password_sniffer.html
        $string7 = ">SniffPass<" nocase ascii wide
        // Description: password monitoring software that listens to your network - capture the passwords that pass through your network adapter and display them on the screen instantly
        // Reference: https://www.nirsoft.net/utils/password_sniffer.html
        $string8 = "1df8e073ca89d026578464b0da9748194ef62c826dea4af9848ef23b3ddf1785" nocase ascii wide
        // Description: password monitoring software that listens to your network - capture the passwords that pass through your network adapter and display them on the screen instantly
        // Reference: https://www.nirsoft.net/utils/password_sniffer.html
        $string9 = "c92580318be4effdb37aa67145748826f6a9e285bc2426410dc280e61e3c7620" nocase ascii wide
        // Description: password monitoring software that listens to your network - capture the passwords that pass through your network adapter and display them on the screen instantly
        // Reference: https://www.nirsoft.net/utils/password_sniffer.html
        $string10 = /http\:\/\/www\.nirsoft\.net\/password_test/ nocase ascii wide
        // Description: password monitoring software that listens to your network - capture the passwords that pass through your network adapter and display them on the screen instantly
        // Reference: https://www.nirsoft.net/utils/password_sniffer.html
        $string11 = "PacketSnifferClass1" nocase ascii wide
        // Description: password monitoring software that listens to your network - capture the passwords that pass through your network adapter and display them on the screen instantly
        // Reference: https://www.nirsoft.net/utils/password_sniffer.html
        $string12 = /SniffPass\.exe/ nocase ascii wide
        // Description: password monitoring software that listens to your network - capture the passwords that pass through your network adapter and display them on the screen instantly
        // Reference: https://www.nirsoft.net/utils/password_sniffer.html
        $string13 = /sniffpass\-x64\.zip/ nocase ascii wide
        // Description: password monitoring software that listens to your network - capture the passwords that pass through your network adapter and display them on the screen instantly
        // Reference: https://www.nirsoft.net/utils/password_sniffer.html
        $string14 = /Software\\NirSoft\\SniffPass/ nocase ascii wide

    condition:
        any of them
}
