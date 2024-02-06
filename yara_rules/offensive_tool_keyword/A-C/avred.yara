rule avred
{
    meta:
        description = "Detection patterns for the tool 'avred' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "avred"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Avred is being used to identify which parts of a file are identified by a Antivirus and tries to show as much possible information and context about each match.
        // Reference: https://github.com/dobin/avred
        $string1 = /\savred\.py\s/ nocase ascii wide
        // Description: Avred is being used to identify which parts of a file are identified by a Antivirus and tries to show as much possible information and context about each match.
        // Reference: https://github.com/dobin/avred
        $string2 = /\savredweb\.py\s/ nocase ascii wide
        // Description: Avred is being used to identify which parts of a file are identified by a Antivirus and tries to show as much possible information and context about each match.
        // Reference: https://github.com/dobin/avred
        $string3 = /\.py\s\-\-file\s.{0,1000}\.ps1\s\-\-server\samsi/ nocase ascii wide
        // Description: Avred is being used to identify which parts of a file are identified by a Antivirus and tries to show as much possible information and context about each match.
        // Reference: https://github.com/dobin/avred
        $string4 = /\.py\s\-\-server\samsi\s\-\-file\s.{0,1000}\.exe/ nocase ascii wide
        // Description: Avred is being used to identify which parts of a file are identified by a Antivirus and tries to show as much possible information and context about each match.
        // Reference: https://github.com/dobin/avred
        $string5 = /\/avred\.git/ nocase ascii wide
        // Description: Avred is being used to identify which parts of a file are identified by a Antivirus and tries to show as much possible information and context about each match.
        // Reference: https://github.com/dobin/avred
        $string6 = /\/avred\.py/ nocase ascii wide
        // Description: Avred is being used to identify which parts of a file are identified by a Antivirus and tries to show as much possible information and context about each match.
        // Reference: https://github.com/dobin/avred
        $string7 = /\/avredweb\.py\s/ nocase ascii wide
        // Description: Avred is being used to identify which parts of a file are identified by a Antivirus and tries to show as much possible information and context about each match.
        // Reference: https://github.com/dobin/avred
        $string8 = /\/dobin\/avred/ nocase ascii wide
        // Description: Avred is being used to identify which parts of a file are identified by a Antivirus and tries to show as much possible information and context about each match.
        // Reference: https://github.com/dobin/avred
        $string9 = /\\avred\.py/ nocase ascii wide
        // Description: Avred is being used to identify which parts of a file are identified by a Antivirus and tries to show as much possible information and context about each match.
        // Reference: https://github.com/dobin/avred
        $string10 = /\\avredweb\.py\s/ nocase ascii wide
        // Description: Avred is being used to identify which parts of a file are identified by a Antivirus and tries to show as much possible information and context about each match.
        // Reference: https://github.com/dobin/avred
        $string11 = /avred\-main\.zip/ nocase ascii wide
        // Description: Avred is being used to identify which parts of a file are identified by a Antivirus and tries to show as much possible information and context about each match.
        // Reference: https://github.com/dobin/avred
        $string12 = /https\:\/\/avred\.r00ted\.ch\/upload/ nocase ascii wide
        // Description: Avred is being used to identify which parts of a file are identified by a Antivirus and tries to show as much possible information and context about each match.
        // Reference: https://github.com/dobin/avred
        $string13 = /podman\srun\s.{0,1000}\s\-\-name\savred\s\-d\savred/ nocase ascii wide

    condition:
        any of them
}
