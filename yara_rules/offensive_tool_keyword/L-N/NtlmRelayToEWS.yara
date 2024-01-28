rule NtlmRelayToEWS
{
    meta:
        description = "Detection patterns for the tool 'NtlmRelayToEWS' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "NtlmRelayToEWS"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: ntlmRelayToEWS is a tool for performing ntlm relay attacks on Exchange Web Services (EWS)
        // Reference: https://github.com/Arno0x/NtlmRelayToEWS
        $string1 = /\shttprelayserver\.py/ nocase ascii wide
        // Description: ntlmRelayToEWS is a tool for performing ntlm relay attacks on Exchange Web Services (EWS)
        // Reference: https://github.com/Arno0x/NtlmRelayToEWS
        $string2 = /\ssmbrelayserver\.py/ nocase ascii wide
        // Description: ntlmRelayToEWS is a tool for performing ntlm relay attacks on Exchange Web Services (EWS)
        // Reference: https://github.com/Arno0x/NtlmRelayToEWS
        $string3 = /\/httprelayserver\.py/ nocase ascii wide
        // Description: ntlmRelayToEWS is a tool for performing ntlm relay attacks on Exchange Web Services (EWS)
        // Reference: https://github.com/Arno0x/NtlmRelayToEWS
        $string4 = /\/NtlmRelayToEWS\.git/ nocase ascii wide
        // Description: ntlmRelayToEWS is a tool for performing ntlm relay attacks on Exchange Web Services (EWS)
        // Reference: https://github.com/Arno0x/NtlmRelayToEWS
        $string5 = /\/NtlmRelayToEWS\// nocase ascii wide
        // Description: ntlmRelayToEWS is a tool for performing ntlm relay attacks on Exchange Web Services (EWS)
        // Reference: https://github.com/Arno0x/NtlmRelayToEWS
        $string6 = /\/smbrelayserver\.py/ nocase ascii wide
        // Description: ntlmRelayToEWS is a tool for performing ntlm relay attacks on Exchange Web Services (EWS)
        // Reference: https://github.com/Arno0x/NtlmRelayToEWS
        $string7 = /\\httprelayserver\.py/ nocase ascii wide
        // Description: ntlmRelayToEWS is a tool for performing ntlm relay attacks on Exchange Web Services (EWS)
        // Reference: https://github.com/Arno0x/NtlmRelayToEWS
        $string8 = /\\NtlmRelayToEWS\\/ nocase ascii wide
        // Description: ntlmRelayToEWS is a tool for performing ntlm relay attacks on Exchange Web Services (EWS)
        // Reference: https://github.com/Arno0x/NtlmRelayToEWS
        $string9 = /\\smbrelayserver\.py/ nocase ascii wide
        // Description: ntlmRelayToEWS is a tool for performing ntlm relay attacks on Exchange Web Services (EWS)
        // Reference: https://github.com/Arno0x/NtlmRelayToEWS
        $string10 = /Arno0x\/NtlmRelayToEWS/ nocase ascii wide
        // Description: ntlmRelayToEWS is a tool for performing ntlm relay attacks on Exchange Web Services (EWS)
        // Reference: https://github.com/Arno0x/NtlmRelayToEWS
        $string11 = /ntlmRelayToEWS\s\-/ nocase ascii wide
        // Description: ntlmRelayToEWS is a tool for performing ntlm relay attacks on Exchange Web Services (EWS)
        // Reference: https://github.com/Arno0x/NtlmRelayToEWS
        $string12 = /ntlmRelayToEWS\.py/ nocase ascii wide
        // Description: ntlmRelayToEWS is a tool for performing ntlm relay attacks on Exchange Web Services (EWS)
        // Reference: https://github.com/Arno0x/NtlmRelayToEWS
        $string13 = /NtlmRelayToEWS\-master/ nocase ascii wide

    condition:
        any of them
}
