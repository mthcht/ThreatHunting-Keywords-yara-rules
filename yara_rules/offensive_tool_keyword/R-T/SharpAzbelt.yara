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
        $string1 = /\/SharpAzbelt\.git/ nocase ascii wide
        // Description: This is an attempt to port Azbelt by Leron Gray from Nim to C#. It can be used to enumerate and pilfer Azure-related credentials from Windows boxes and Azure IaaS resources
        // Reference: https://github.com/redskal/SharpAzbelt
        $string2 = /\[\!\]\s\s\s\sFailed\sto\senumerate\sCredman\:/ nocase ascii wide
        // Description: This is an attempt to port Azbelt by Leron Gray from Nim to C#. It can be used to enumerate and pilfer Azure-related credentials from Windows boxes and Azure IaaS resources
        // Reference: https://github.com/redskal/SharpAzbelt
        $string3 = /\[i\]\sAAD\sJoin\:.{0,1000}enumerate/ nocase ascii wide
        // Description: This is an attempt to port Azbelt by Leron Gray from Nim to C#. It can be used to enumerate and pilfer Azure-related credentials from Windows boxes and Azure IaaS resources
        // Reference: https://github.com/redskal/SharpAzbelt
        $string4 = /\[i\]\sCredman\:.{0,1000}Credential\sBlob\sDecrypted/ nocase ascii wide
        // Description: This is an attempt to port Azbelt by Leron Gray from Nim to C#. It can be used to enumerate and pilfer Azure-related credentials from Windows boxes and Azure IaaS resources
        // Reference: https://github.com/redskal/SharpAzbelt
        $string5 = /\\SharpAzbelt\.csproj/ nocase ascii wide
        // Description: This is an attempt to port Azbelt by Leron Gray from Nim to C#. It can be used to enumerate and pilfer Azure-related credentials from Windows boxes and Azure IaaS resources
        // Reference: https://github.com/redskal/SharpAzbelt
        $string6 = /\\SharpAzbelt\.exe/ nocase ascii wide
        // Description: This is an attempt to port Azbelt by Leron Gray from Nim to C#. It can be used to enumerate and pilfer Azure-related credentials from Windows boxes and Azure IaaS resources
        // Reference: https://github.com/redskal/SharpAzbelt
        $string7 = /\\SharpAzbelt\.sln/ nocase ascii wide
        // Description: This is an attempt to port Azbelt by Leron Gray from Nim to C#. It can be used to enumerate and pilfer Azure-related credentials from Windows boxes and Azure IaaS resources
        // Reference: https://github.com/redskal/SharpAzbelt
        $string8 = /57D4D4F4\-F083\-47A3\-AE33\-AE2500ABA3B6/ nocase ascii wide
        // Description: This is an attempt to port Azbelt by Leron Gray from Nim to C#. It can be used to enumerate and pilfer Azure-related credentials from Windows boxes and Azure IaaS resources
        // Reference: https://github.com/redskal/SharpAzbelt
        $string9 = /ParseMSALCache.{0,1000}\.azure\\msal_token_cache\.bin/ nocase ascii wide
        // Description: This is an attempt to port Azbelt by Leron Gray from Nim to C#. It can be used to enumerate and pilfer Azure-related credentials from Windows boxes and Azure IaaS resources
        // Reference: https://github.com/redskal/SharpAzbelt
        $string10 = /ParseMSALCache.{0,1000}Appdata\\Local\\\.IdentityService\\msal\.cache/ nocase ascii wide
        // Description: This is an attempt to port Azbelt by Leron Gray from Nim to C#. It can be used to enumerate and pilfer Azure-related credentials from Windows boxes and Azure IaaS resources
        // Reference: https://github.com/redskal/SharpAzbelt
        $string11 = /redskal\/SharpAzbelt/ nocase ascii wide
        // Description: This is an attempt to port Azbelt by Leron Gray from Nim to C#. It can be used to enumerate and pilfer Azure-related credentials from Windows boxes and Azure IaaS resources
        // Reference: https://github.com/redskal/SharpAzbelt
        $string12 = /SharpAzbelt\-main/ nocase ascii wide

    condition:
        any of them
}
