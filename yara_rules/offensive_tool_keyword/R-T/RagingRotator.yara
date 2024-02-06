rule RagingRotator
{
    meta:
        description = "Detection patterns for the tool 'RagingRotator' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "RagingRotator"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A tool for carrying out brute force attacks against Office 365 with built in IP rotation use AWS gateways.
        // Reference: https://github.com/nickzer0/RagingRotator
        $string1 = /\sRagingRotator\.go/ nocase ascii wide
        // Description: A tool for carrying out brute force attacks against Office 365 with built in IP rotation use AWS gateways.
        // Reference: https://github.com/nickzer0/RagingRotator
        $string2 = /\s\-userpassfile\s\.\/userpass_file\.txt/ nocase ascii wide
        // Description: A tool for carrying out brute force attacks against Office 365 with built in IP rotation use AWS gateways.
        // Reference: https://github.com/nickzer0/RagingRotator
        $string3 = /\/RagingRotator\.git/ nocase ascii wide
        // Description: A tool for carrying out brute force attacks against Office 365 with built in IP rotation use AWS gateways.
        // Reference: https://github.com/nickzer0/RagingRotator
        $string4 = /\/RagingRotator\.go/ nocase ascii wide
        // Description: A tool for carrying out brute force attacks against Office 365 with built in IP rotation use AWS gateways.
        // Reference: https://github.com/nickzer0/RagingRotator
        $string5 = /\[\!\]\sValid\slogin.{0,1000}\sexpired\spassword\:\s/ nocase ascii wide
        // Description: A tool for carrying out brute force attacks against Office 365 with built in IP rotation use AWS gateways.
        // Reference: https://github.com/nickzer0/RagingRotator
        $string6 = /\[\+\]\sValid\slogin.{0,1000}\suser\smust\senroll\sin\sMFA\./ nocase ascii wide
        // Description: A tool for carrying out brute force attacks against Office 365 with built in IP rotation use AWS gateways.
        // Reference: https://github.com/nickzer0/RagingRotator
        $string7 = /\\RagingRotator\.go/ nocase ascii wide
        // Description: A tool for carrying out brute force attacks against Office 365 with built in IP rotation use AWS gateways.
        // Reference: https://github.com/nickzer0/RagingRotator
        $string8 = /nickzer0\/RagingRotator/ nocase ascii wide
        // Description: A tool for carrying out brute force attacks against Office 365 with built in IP rotation use AWS gateways.
        // Reference: https://github.com/nickzer0/RagingRotator
        $string9 = /RagingRotator\-main\./ nocase ascii wide

    condition:
        any of them
}
