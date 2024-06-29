rule PewPewPew
{
    meta:
        description = "Detection patterns for the tool 'PewPewPew' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PewPewPew"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: host a script on a PowerShell webserver, invoke the IEX download cradle to download/execute the target code and post the results back to the server
        // Reference: https://github.com/PowerShellEmpire/PowerTools
        $string1 = /8b27ef8f7cbae47922e672618e39abe7fa626c7405a67b12d7a88c1da8b06cad/ nocase ascii wide
        // Description: host a script on a PowerShell webserver, invoke the IEX download cradle to download/execute the target code and post the results back to the server
        // Reference: https://github.com/PowerShellEmpire/PowerTools
        $string2 = /95f9539c17bfa24ee0d7206b1fb2b195885b94e82d6bd7276bfccf2f0ceb9ac4/ nocase ascii wide
        // Description: host a script on a PowerShell webserver, invoke the IEX download cradle to download/execute the target code and post the results back to the server
        // Reference: https://github.com/PowerShellEmpire/PowerTools
        $string3 = /a591699874d0a2c26c1d9e47561ee2a3043fc3ea458c09a7ab8a24a25150cd0a/ nocase ascii wide
        // Description: host a script on a PowerShell webserver, invoke the IEX download cradle to download/execute the target code and post the results back to the server
        // Reference: https://github.com/PowerShellEmpire/PowerTools
        $string4 = /f392e058d65cc84f23773a88424d5a9e6a6987f790c52e0fb032e8538b5aec36/ nocase ascii wide
        // Description: host a script on a PowerShell webserver, invoke the IEX download cradle to download/execute the target code and post the results back to the server
        // Reference: https://github.com/PowerShellEmpire/PowerTools
        $string5 = /Invoke\-MassCommand\.ps1/ nocase ascii wide
        // Description: host a script on a PowerShell webserver, invoke the IEX download cradle to download/execute the target code and post the results back to the server
        // Reference: https://github.com/PowerShellEmpire/PowerTools
        $string6 = /Invoke\-MassMimikatz/ nocase ascii wide
        // Description: host a script on a PowerShell webserver, invoke the IEX download cradle to download/execute the target code and post the results back to the server
        // Reference: https://github.com/PowerShellEmpire/PowerTools
        $string7 = /Invoke\-MassSearch\.ps1/ nocase ascii wide
        // Description: host a script on a PowerShell webserver, invoke the IEX download cradle to download/execute the target code and post the results back to the server
        // Reference: https://github.com/PowerShellEmpire/PowerTools
        $string8 = /Invoke\-MassTokens\.ps1/ nocase ascii wide
        // Description: host a script on a PowerShell webserver, invoke the IEX download cradle to download/execute the target code and post the results back to the server
        // Reference: https://github.com/PowerShellEmpire/PowerTools
        $string9 = /Invoke\-TokenManipulation\s\-CreateProcess\s.{0,1000}cmd\.exe/ nocase ascii wide

    condition:
        any of them
}
