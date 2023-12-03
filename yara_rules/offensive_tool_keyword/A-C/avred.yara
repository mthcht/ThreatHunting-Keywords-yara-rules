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
        $string1 = /.{0,1000}\savred\.py\s.{0,1000}/ nocase ascii wide
        // Description: Avred is being used to identify which parts of a file are identified by a Antivirus and tries to show as much possible information and context about each match.
        // Reference: https://github.com/dobin/avred
        $string2 = /.{0,1000}\savredweb\.py\s.{0,1000}/ nocase ascii wide
        // Description: Avred is being used to identify which parts of a file are identified by a Antivirus and tries to show as much possible information and context about each match.
        // Reference: https://github.com/dobin/avred
        $string3 = /.{0,1000}\.py\s\-\-file\s.{0,1000}\.ps1\s\-\-server\samsi.{0,1000}/ nocase ascii wide
        // Description: Avred is being used to identify which parts of a file are identified by a Antivirus and tries to show as much possible information and context about each match.
        // Reference: https://github.com/dobin/avred
        $string4 = /.{0,1000}\.py\s\-\-server\samsi\s\-\-file\s.{0,1000}\.exe.{0,1000}/ nocase ascii wide
        // Description: Avred is being used to identify which parts of a file are identified by a Antivirus and tries to show as much possible information and context about each match.
        // Reference: https://github.com/dobin/avred
        $string5 = /.{0,1000}\/avred\.git.{0,1000}/ nocase ascii wide
        // Description: Avred is being used to identify which parts of a file are identified by a Antivirus and tries to show as much possible information and context about each match.
        // Reference: https://github.com/dobin/avred
        $string6 = /.{0,1000}\/avred\.py.{0,1000}/ nocase ascii wide
        // Description: Avred is being used to identify which parts of a file are identified by a Antivirus and tries to show as much possible information and context about each match.
        // Reference: https://github.com/dobin/avred
        $string7 = /.{0,1000}\/avredweb\.py\s.{0,1000}/ nocase ascii wide
        // Description: Avred is being used to identify which parts of a file are identified by a Antivirus and tries to show as much possible information and context about each match.
        // Reference: https://github.com/dobin/avred
        $string8 = /.{0,1000}\/dobin\/avred.{0,1000}/ nocase ascii wide
        // Description: Avred is being used to identify which parts of a file are identified by a Antivirus and tries to show as much possible information and context about each match.
        // Reference: https://github.com/dobin/avred
        $string9 = /.{0,1000}\\avred\.py.{0,1000}/ nocase ascii wide
        // Description: Avred is being used to identify which parts of a file are identified by a Antivirus and tries to show as much possible information and context about each match.
        // Reference: https://github.com/dobin/avred
        $string10 = /.{0,1000}\\avredweb\.py\s.{0,1000}/ nocase ascii wide
        // Description: Avred is being used to identify which parts of a file are identified by a Antivirus and tries to show as much possible information and context about each match.
        // Reference: https://github.com/dobin/avred
        $string11 = /.{0,1000}avred\-main\.zip.{0,1000}/ nocase ascii wide
        // Description: Avred is being used to identify which parts of a file are identified by a Antivirus and tries to show as much possible information and context about each match.
        // Reference: https://github.com/dobin/avred
        $string12 = /.{0,1000}https:\/\/avred\.r00ted\.ch\/upload.{0,1000}/ nocase ascii wide
        // Description: Avred is being used to identify which parts of a file are identified by a Antivirus and tries to show as much possible information and context about each match.
        // Reference: https://github.com/dobin/avred
        $string13 = /.{0,1000}podman\srun\s.{0,1000}\s\-\-name\savred\s\-d\savred.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
