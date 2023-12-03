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
        $string1 = /.{0,1000}\sRagingRotator\.go.{0,1000}/ nocase ascii wide
        // Description: A tool for carrying out brute force attacks against Office 365 with built in IP rotation use AWS gateways.
        // Reference: https://github.com/nickzer0/RagingRotator
        $string2 = /.{0,1000}\s\-userpassfile\s\.\/userpass_file\.txt.{0,1000}/ nocase ascii wide
        // Description: A tool for carrying out brute force attacks against Office 365 with built in IP rotation use AWS gateways.
        // Reference: https://github.com/nickzer0/RagingRotator
        $string3 = /.{0,1000}\/RagingRotator\.git.{0,1000}/ nocase ascii wide
        // Description: A tool for carrying out brute force attacks against Office 365 with built in IP rotation use AWS gateways.
        // Reference: https://github.com/nickzer0/RagingRotator
        $string4 = /.{0,1000}\/RagingRotator\.go.{0,1000}/ nocase ascii wide
        // Description: A tool for carrying out brute force attacks against Office 365 with built in IP rotation use AWS gateways.
        // Reference: https://github.com/nickzer0/RagingRotator
        $string5 = /.{0,1000}\[\!\]\sValid\slogin,\sexpired\spassword:\s.{0,1000}/ nocase ascii wide
        // Description: A tool for carrying out brute force attacks against Office 365 with built in IP rotation use AWS gateways.
        // Reference: https://github.com/nickzer0/RagingRotator
        $string6 = /.{0,1000}\[\+\]\sValid\slogin,\suser\smust\senroll\sin\sMFA\..{0,1000}/ nocase ascii wide
        // Description: A tool for carrying out brute force attacks against Office 365 with built in IP rotation use AWS gateways.
        // Reference: https://github.com/nickzer0/RagingRotator
        $string7 = /.{0,1000}\\RagingRotator\.go.{0,1000}/ nocase ascii wide
        // Description: A tool for carrying out brute force attacks against Office 365 with built in IP rotation use AWS gateways.
        // Reference: https://github.com/nickzer0/RagingRotator
        $string8 = /.{0,1000}nickzer0\/RagingRotator.{0,1000}/ nocase ascii wide
        // Description: A tool for carrying out brute force attacks against Office 365 with built in IP rotation use AWS gateways.
        // Reference: https://github.com/nickzer0/RagingRotator
        $string9 = /.{0,1000}RagingRotator\-main\..{0,1000}/ nocase ascii wide

    condition:
        any of them
}
