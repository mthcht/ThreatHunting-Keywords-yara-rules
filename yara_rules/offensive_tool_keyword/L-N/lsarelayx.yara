rule lsarelayx
{
    meta:
        description = "Detection patterns for the tool 'lsarelayx' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "lsarelayx"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: lsarelayx is system wide NTLM relay tool designed to relay incoming NTLM based authentication to the host it is running on
        // Reference: https://github.com/CCob/lsarelayx
        $string1 = /\/lsarelayx\.git/ nocase ascii wide
        // Description: lsarelayx is system wide NTLM relay tool designed to relay incoming NTLM based authentication to the host it is running on
        // Reference: https://github.com/CCob/lsarelayx
        $string2 = /\/root\/lsarelayx/ nocase ascii wide
        // Description: lsarelayx is system wide NTLM relay tool designed to relay incoming NTLM based authentication to the host it is running on
        // Reference: https://github.com/CCob/lsarelayx
        $string3 = /\\\\\.\\\\pipe\\\\lsarelayx/ nocase ascii wide
        // Description: lsarelayx is system wide NTLM relay tool designed to relay incoming NTLM based authentication to the host it is running on
        // Reference: https://github.com/CCob/lsarelayx
        $string4 = /\\liblsarelay\.dll/ nocase ascii wide
        // Description: lsarelayx is system wide NTLM relay tool designed to relay incoming NTLM based authentication to the host it is running on
        // Reference: https://github.com/CCob/lsarelayx
        $string5 = /\\liblsarelayx\.dll/ nocase ascii wide
        // Description: lsarelayx is system wide NTLM relay tool designed to relay incoming NTLM based authentication to the host it is running on
        // Reference: https://github.com/CCob/lsarelayx
        $string6 = /\\lsarelayx\.cpp/ nocase ascii wide
        // Description: lsarelayx is system wide NTLM relay tool designed to relay incoming NTLM based authentication to the host it is running on
        // Reference: https://github.com/CCob/lsarelayx
        $string7 = /\\lsarelayx\.csproj/ nocase ascii wide
        // Description: lsarelayx is system wide NTLM relay tool designed to relay incoming NTLM based authentication to the host it is running on
        // Reference: https://github.com/CCob/lsarelayx
        $string8 = /\\lsarelayx\.sln/ nocase ascii wide
        // Description: lsarelayx is system wide NTLM relay tool designed to relay incoming NTLM based authentication to the host it is running on
        // Reference: https://github.com/CCob/lsarelayx
        $string9 = /CCob\/lsarelayx/ nocase ascii wide
        // Description: lsarelayx is system wide NTLM relay tool designed to relay incoming NTLM based authentication to the host it is running on
        // Reference: https://github.com/CCob/lsarelayx
        $string10 = /Initialised\slsarelayx/ nocase ascii wide
        // Description: lsarelayx is system wide NTLM relay tool designed to relay incoming NTLM based authentication to the host it is running on
        // Reference: https://github.com/CCob/lsarelayx
        $string11 = /lsarelayx\sStarting\.\.\.\./ nocase ascii wide
        // Description: lsarelayx is system wide NTLM relay tool designed to relay incoming NTLM based authentication to the host it is running on
        // Reference: https://github.com/CCob/lsarelayx
        $string12 = /lsarelayx\.exe/ nocase ascii wide
        // Description: lsarelayx is system wide NTLM relay tool designed to relay incoming NTLM based authentication to the host it is running on
        // Reference: https://github.com/CCob/lsarelayx
        $string13 = /lsarelayx_0\.1_ALPHA\.zip/ nocase ascii wide
        // Description: lsarelayx is system wide NTLM relay tool designed to relay incoming NTLM based authentication to the host it is running on
        // Reference: https://github.com/CCob/lsarelayx
        $string14 = /ntlmrelayx\.py/ nocase ascii wide
        // Description: lsarelayx is system wide NTLM relay tool designed to relay incoming NTLM based authentication to the host it is running on
        // Reference: https://github.com/CCob/lsarelayx
        $string15 = /\-smb2support\s\-\-no\-wcf\-server\s\-\-no\-smb\-server\s\-\-no\-http\-server/ nocase ascii wide

    condition:
        any of them
}
