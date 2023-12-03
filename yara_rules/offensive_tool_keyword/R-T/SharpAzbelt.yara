rule SharpAzbelt
{
    meta:
        description = "Detection patterns for the tool 'SharpAzbelt' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpAzbelt"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: This is an attempt to port Azbelt by Leron Gray from Nim to C#. It can be used to enumerate and pilfer Azure-related credentials from Windows boxes and Azure IaaS resources
        // Reference: https://github.com/redskal/SharpAzbelt
        $string1 = /.{0,1000}\/SharpAzbelt\.git.{0,1000}/ nocase ascii wide
        // Description: This is an attempt to port Azbelt by Leron Gray from Nim to C#. It can be used to enumerate and pilfer Azure-related credentials from Windows boxes and Azure IaaS resources
        // Reference: https://github.com/redskal/SharpAzbelt
        $string2 = /.{0,1000}\[\!\]\s\s\s\sFailed\sto\senumerate\sCredman:.{0,1000}/ nocase ascii wide
        // Description: This is an attempt to port Azbelt by Leron Gray from Nim to C#. It can be used to enumerate and pilfer Azure-related credentials from Windows boxes and Azure IaaS resources
        // Reference: https://github.com/redskal/SharpAzbelt
        $string3 = /.{0,1000}\[i\]\sAAD\sJoin:.{0,1000}enumerate.{0,1000}/ nocase ascii wide
        // Description: This is an attempt to port Azbelt by Leron Gray from Nim to C#. It can be used to enumerate and pilfer Azure-related credentials from Windows boxes and Azure IaaS resources
        // Reference: https://github.com/redskal/SharpAzbelt
        $string4 = /.{0,1000}\[i\]\sCredman:.{0,1000}Credential\sBlob\sDecrypted.{0,1000}/ nocase ascii wide
        // Description: This is an attempt to port Azbelt by Leron Gray from Nim to C#. It can be used to enumerate and pilfer Azure-related credentials from Windows boxes and Azure IaaS resources
        // Reference: https://github.com/redskal/SharpAzbelt
        $string5 = /.{0,1000}\\SharpAzbelt\.csproj.{0,1000}/ nocase ascii wide
        // Description: This is an attempt to port Azbelt by Leron Gray from Nim to C#. It can be used to enumerate and pilfer Azure-related credentials from Windows boxes and Azure IaaS resources
        // Reference: https://github.com/redskal/SharpAzbelt
        $string6 = /.{0,1000}\\SharpAzbelt\.exe.{0,1000}/ nocase ascii wide
        // Description: This is an attempt to port Azbelt by Leron Gray from Nim to C#. It can be used to enumerate and pilfer Azure-related credentials from Windows boxes and Azure IaaS resources
        // Reference: https://github.com/redskal/SharpAzbelt
        $string7 = /.{0,1000}\\SharpAzbelt\.sln.{0,1000}/ nocase ascii wide
        // Description: This is an attempt to port Azbelt by Leron Gray from Nim to C#. It can be used to enumerate and pilfer Azure-related credentials from Windows boxes and Azure IaaS resources
        // Reference: https://github.com/redskal/SharpAzbelt
        $string8 = /.{0,1000}57D4D4F4\-F083\-47A3\-AE33\-AE2500ABA3B6.{0,1000}/ nocase ascii wide
        // Description: This is an attempt to port Azbelt by Leron Gray from Nim to C#. It can be used to enumerate and pilfer Azure-related credentials from Windows boxes and Azure IaaS resources
        // Reference: https://github.com/redskal/SharpAzbelt
        $string9 = /.{0,1000}ParseMSALCache.{0,1000}\.azure\\msal_token_cache\.bin.{0,1000}/ nocase ascii wide
        // Description: This is an attempt to port Azbelt by Leron Gray from Nim to C#. It can be used to enumerate and pilfer Azure-related credentials from Windows boxes and Azure IaaS resources
        // Reference: https://github.com/redskal/SharpAzbelt
        $string10 = /.{0,1000}ParseMSALCache.{0,1000}Appdata\\Local\\\.IdentityService\\msal\.cache.{0,1000}/ nocase ascii wide
        // Description: This is an attempt to port Azbelt by Leron Gray from Nim to C#. It can be used to enumerate and pilfer Azure-related credentials from Windows boxes and Azure IaaS resources
        // Reference: https://github.com/redskal/SharpAzbelt
        $string11 = /.{0,1000}redskal\/SharpAzbelt.{0,1000}/ nocase ascii wide
        // Description: This is an attempt to port Azbelt by Leron Gray from Nim to C#. It can be used to enumerate and pilfer Azure-related credentials from Windows boxes and Azure IaaS resources
        // Reference: https://github.com/redskal/SharpAzbelt
        $string12 = /.{0,1000}SharpAzbelt\-main.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
