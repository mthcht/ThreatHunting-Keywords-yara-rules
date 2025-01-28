rule credhistview
{
    meta:
        description = "Detection patterns for the tool 'credhistview' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "credhistview"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: This tool allows you to decrypt the CREDHIST file and view the SHA1 and NTLM hashes of all previous passwords you used on your system
        // Reference: https://www.nirsoft.net/utils/credhist_view.html
        $string1 = /\\CredHistView\.cfg/ nocase ascii wide
        // Description: This tool allows you to decrypt the CREDHIST file and view the SHA1 and NTLM hashes of all previous passwords you used on your system
        // Reference: https://www.nirsoft.net/utils/credhist_view.html
        $string2 = /\\credhistview\.lnk/ nocase ascii wide
        // Description: This tool allows you to decrypt the CREDHIST file and view the SHA1 and NTLM hashes of all previous passwords you used on your system
        // Reference: https://www.nirsoft.net/utils/credhist_view.html
        $string3 = /\\credhistview\\/ nocase ascii wide
        // Description: This tool allows you to decrypt the CREDHIST file and view the SHA1 and NTLM hashes of all previous passwords you used on your system
        // Reference: https://www.nirsoft.net/utils/credhist_view.html
        $string4 = /\>Don\sHO\sdon\.h\@free\.fr\</ nocase ascii wide
        // Description: This tool allows you to decrypt the CREDHIST file and view the SHA1 and NTLM hashes of all previous passwords you used on your system
        // Reference: https://www.nirsoft.net/utils/credhist_view.html
        $string5 = /CredHistView\.exe/ nocase ascii wide
        // Description: This tool allows you to decrypt the CREDHIST file and view the SHA1 and NTLM hashes of all previous passwords you used on your system
        // Reference: https://www.nirsoft.net/utils/credhist_view.html
        $string6 = /credhistview\.zip/ nocase ascii wide

    condition:
        any of them
}
