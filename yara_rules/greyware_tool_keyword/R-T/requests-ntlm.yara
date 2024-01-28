rule requests_ntlm
{
    meta:
        description = "Detection patterns for the tool 'requests-ntlm' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "requests-ntlm"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: HTTP NTLM Authentication for Requests Library
        // Reference: https://pypi.org/project/requests-ntlm/
        $string1 = /\sinstall\srequests_ntlm/ nocase ascii wide
        // Description: HTTP NTLM Authentication for Requests Library
        // Reference: https://pypi.org/project/requests-ntlm/
        $string2 = /from\srequests_ntlm\simport\sHttpNtlmAuth/ nocase ascii wide

    condition:
        any of them
}
