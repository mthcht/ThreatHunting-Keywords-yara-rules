rule DecryptRDCManager
{
    meta:
        description = "Detection patterns for the tool 'DecryptRDCManager' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "DecryptRDCManager"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: decrypts passwords stored in Remote Desktop Connection Manager (RDCMan) using DPAPI
        // Reference: https://github.com/mez-0/DecryptRDCManager
        $string1 = /\/DecryptRDCManager\.git/ nocase ascii wide
        // Description: decrypts passwords stored in Remote Desktop Connection Manager (RDCMan) using DPAPI
        // Reference: https://github.com/mez-0/DecryptRDCManager
        $string2 = /\\DecryptRDCManager\.sln/ nocase ascii wide
        // Description: decrypts passwords stored in Remote Desktop Connection Manager (RDCMan) using DPAPI
        // Reference: https://github.com/mez-0/DecryptRDCManager
        $string3 = "af91c925c3a6ba14dea50a5d24593c48cc02e7bfc23b7a02eaf59dd55c3ae6cd" nocase ascii wide
        // Description: decrypts passwords stored in Remote Desktop Connection Manager (RDCMan) using DPAPI
        // Reference: https://github.com/mez-0/DecryptRDCManager
        $string4 = "CF924967-0AEC-43B2-B891-D67B6DB9F523" nocase ascii wide
        // Description: decrypts passwords stored in Remote Desktop Connection Manager (RDCMan) using DPAPI
        // Reference: https://github.com/mez-0/DecryptRDCManager
        $string5 = /Decrypt\-RDCMan\.ps1/ nocase ascii wide
        // Description: decrypts passwords stored in Remote Desktop Connection Manager (RDCMan) using DPAPI
        // Reference: https://github.com/mez-0/DecryptRDCManager
        $string6 = /DecryptRDCManager\.exe/ nocase ascii wide
        // Description: decrypts passwords stored in Remote Desktop Connection Manager (RDCMan) using DPAPI
        // Reference: https://github.com/mez-0/DecryptRDCManager
        $string7 = "mez-0/DecryptRDCManager" nocase ascii wide

    condition:
        any of them
}
