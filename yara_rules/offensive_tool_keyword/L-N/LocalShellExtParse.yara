rule LocalShellExtParse
{
    meta:
        description = "Detection patterns for the tool 'LocalShellExtParse' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "LocalShellExtParse"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Script to parse first load time for Shell Extensions loaded by user. Also enumerates all loaded Shell Extensions that are only installed for the Current User.
        // Reference: https://github.com/herrcore/LocalShellExtParse
        $string1 = /\sLocalShellExtParse\.py/ nocase ascii wide
        // Description: Script to parse first load time for Shell Extensions loaded by user. Also enumerates all loaded Shell Extensions that are only installed for the Current User.
        // Reference: https://github.com/herrcore/LocalShellExtParse
        $string2 = /\.py\s\-\-cached\s\-\-ntuser\sNTUSER\.DAT/ nocase ascii wide
        // Description: Script to parse first load time for Shell Extensions loaded by user. Also enumerates all loaded Shell Extensions that are only installed for the Current User.
        // Reference: https://github.com/herrcore/LocalShellExtParse
        $string3 = /\.py\s\-\-ntuser\sNTUSER\.DAT\s\-\-usrclass\sUsrClass\.dat/ nocase ascii wide
        // Description: Script to parse first load time for Shell Extensions loaded by user. Also enumerates all loaded Shell Extensions that are only installed for the Current User.
        // Reference: https://github.com/herrcore/LocalShellExtParse
        $string4 = /\/LocalShellExtParse\.git/ nocase ascii wide
        // Description: Script to parse first load time for Shell Extensions loaded by user. Also enumerates all loaded Shell Extensions that are only installed for the Current User.
        // Reference: https://github.com/herrcore/LocalShellExtParse
        $string5 = /\/LocalShellExtParse\.py/ nocase ascii wide
        // Description: Script to parse first load time for Shell Extensions loaded by user. Also enumerates all loaded Shell Extensions that are only installed for the Current User.
        // Reference: https://github.com/herrcore/LocalShellExtParse
        $string6 = /\\LocalShellExtParse\.py/ nocase ascii wide
        // Description: Script to parse first load time for Shell Extensions loaded by user. Also enumerates all loaded Shell Extensions that are only installed for the Current User.
        // Reference: https://github.com/herrcore/LocalShellExtParse
        $string7 = /\\LocalShellExtParse\-master/ nocase ascii wide
        // Description: Script to parse first load time for Shell Extensions loaded by user. Also enumerates all loaded Shell Extensions that are only installed for the Current User.
        // Reference: https://github.com/herrcore/LocalShellExtParse
        $string8 = /c3a499f047b670e888a41b33749ffc9227b7b0bcc4e9f0882d272918ee3a17d1/ nocase ascii wide
        // Description: Script to parse first load time for Shell Extensions loaded by user. Also enumerates all loaded Shell Extensions that are only installed for the Current User.
        // Reference: https://github.com/herrcore/LocalShellExtParse
        $string9 = /herrcore\/LocalShellExtParse/ nocase ascii wide

    condition:
        any of them
}
