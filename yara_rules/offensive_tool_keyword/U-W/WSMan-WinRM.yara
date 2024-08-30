rule WSMan_WinRM
{
    meta:
        description = "Detection patterns for the tool 'WSMan-WinRM' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "WSMan-WinRM"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: remote commands over WinRM using the WSMan.Automation COM object
        // Reference: https://github.com/bohops/WSMan-WinRM
        $string1 = /\sSharpWSManWinRM\.vbs/ nocase ascii wide
        // Description: remote commands over WinRM using the WSMan.Automation COM object
        // Reference: https://github.com/bohops/WSMan-WinRM
        $string2 = /\sWSManWinRM\.js\s/ nocase ascii wide
        // Description: remote commands over WinRM using the WSMan.Automation COM object
        // Reference: https://github.com/bohops/WSMan-WinRM
        $string3 = /\sWSManWinRM\.ps1/ nocase ascii wide
        // Description: remote commands over WinRM using the WSMan.Automation COM object
        // Reference: https://github.com/bohops/WSMan-WinRM
        $string4 = /\/CppWSManWinRM\.exe/ nocase ascii wide
        // Description: remote commands over WinRM using the WSMan.Automation COM object
        // Reference: https://github.com/bohops/WSMan-WinRM
        $string5 = /\/SharpWSManWinRM\.vbs/ nocase ascii wide
        // Description: remote commands over WinRM using the WSMan.Automation COM object
        // Reference: https://github.com/bohops/WSMan-WinRM
        $string6 = /\/WSMan\-WinRM\.git/ nocase ascii wide
        // Description: remote commands over WinRM using the WSMan.Automation COM object
        // Reference: https://github.com/bohops/WSMan-WinRM
        $string7 = /\/WSManWinRM\.ps1/ nocase ascii wide
        // Description: remote commands over WinRM using the WSMan.Automation COM object
        // Reference: https://github.com/bohops/WSMan-WinRM
        $string8 = /\\CppWSManWinRM\.exe/ nocase ascii wide
        // Description: remote commands over WinRM using the WSMan.Automation COM object
        // Reference: https://github.com/bohops/WSMan-WinRM
        $string9 = /\\SharpWSManWinRM\.cs/ nocase ascii wide
        // Description: remote commands over WinRM using the WSMan.Automation COM object
        // Reference: https://github.com/bohops/WSMan-WinRM
        $string10 = /\\SharpWSManWinRM\.vbs/ nocase ascii wide
        // Description: remote commands over WinRM using the WSMan.Automation COM object
        // Reference: https://github.com/bohops/WSMan-WinRM
        $string11 = /\\WSManWinRM\.ps1/ nocase ascii wide
        // Description: remote commands over WinRM using the WSMan.Automation COM object
        // Reference: https://github.com/bohops/WSMan-WinRM
        $string12 = /80ea8260d6148c716cf35ae8d8621a41b95cf4cd5857392698f1f21f62f2cb8e/ nocase ascii wide
        // Description: remote commands over WinRM using the WSMan.Automation COM object
        // Reference: https://github.com/bohops/WSMan-WinRM
        $string13 = /8478fe6c22a45230e79b057d13439a7ebc0e1a5054d14abbd3c8317add565a40/ nocase ascii wide
        // Description: remote commands over WinRM using the WSMan.Automation COM object
        // Reference: https://github.com/bohops/WSMan-WinRM
        $string14 = /8d8504a63c64c3cd8cd265846b04aef38128987c88bc9ca46144f85741e1fd33/ nocase ascii wide
        // Description: remote commands over WinRM using the WSMan.Automation COM object
        // Reference: https://github.com/bohops/WSMan-WinRM
        $string15 = /bohops\/WSMan\-WinRM/ nocase ascii wide
        // Description: remote commands over WinRM using the WSMan.Automation COM object
        // Reference: https://github.com/bohops/WSMan-WinRM
        $string16 = /ec002016f00ae6f232c1d5e166e5a01e48d3b25302e96a69d87fbf3fc8f05e50/ nocase ascii wide
        // Description: remote commands over WinRM using the WSMan.Automation COM object
        // Reference: https://github.com/bohops/WSMan-WinRM
        $string17 = /ed0a5937431223b74f639b0446fb35e05cd86cef2a752d5dd53d46555cee5e9b/ nocase ascii wide
        // Description: remote commands over WinRM using the WSMan.Automation COM object
        // Reference: https://github.com/bohops/WSMan-WinRM
        $string18 = /SharpWSManWinRM\.exe/ nocase ascii wide

    condition:
        any of them
}
