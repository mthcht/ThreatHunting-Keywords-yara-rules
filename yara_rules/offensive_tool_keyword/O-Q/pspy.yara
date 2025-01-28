rule pspy
{
    meta:
        description = "Detection patterns for the tool 'pspy' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "pspy"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Monitor linux processes without root permissions
        // Reference: https://github.com/DominicBreuker/pspy
        $string1 = "/bin/pspsy"
        // Description: Monitor linux processes without root permissions
        // Reference: https://github.com/DominicBreuker/pspy
        $string2 = /\/download\/v1\.1\.0\/pspy32/
        // Description: Monitor linux processes without root permissions
        // Reference: https://github.com/DominicBreuker/pspy
        $string3 = /\/download\/v1\.1\.0\/pspy64/
        // Description: Monitor linux processes without root permissions
        // Reference: https://github.com/DominicBreuker/pspy
        $string4 = /\/download\/v1\.2\.0\/pspy32/
        // Description: Monitor linux processes without root permissions
        // Reference: https://github.com/DominicBreuker/pspy
        $string5 = /\/download\/v1\.2\.1\/pspy32/
        // Description: Monitor linux processes without root permissions
        // Reference: https://github.com/DominicBreuker/pspy
        $string6 = /\/download\/v1\.2\.1\/pspy64/
        // Description: Monitor linux processes without root permissions
        // Reference: https://github.com/DominicBreuker/pspy
        $string7 = "/pspy -"
        // Description: Monitor linux processes without root permissions
        // Reference: https://github.com/DominicBreuker/pspy
        $string8 = /\/pspy\.git/
        // Description: Monitor linux processes without root permissions
        // Reference: https://github.com/DominicBreuker/pspy
        $string9 = /\/pspy\.git/
        // Description: Monitor linux processes without root permissions
        // Reference: https://github.com/DominicBreuker/pspy
        $string10 = /\/pspy\.go/
        // Description: Monitor linux processes without root permissions
        // Reference: https://github.com/DominicBreuker/pspy
        $string11 = "/pspy/cmd"
        // Description: Monitor linux processes without root permissions
        // Reference: https://github.com/DominicBreuker/pspy
        $string12 = "/pspy/cmd/"
        // Description: Monitor linux processes without root permissions
        // Reference: https://github.com/DominicBreuker/pspy
        $string13 = /\/pspy\/pspy\.go/
        // Description: Monitor linux processes without root permissions
        // Reference: https://github.com/DominicBreuker/pspy
        $string14 = "/pspy32"
        // Description: Monitor linux processes without root permissions
        // Reference: https://github.com/DominicBreuker/pspy
        $string15 = "/pspy64"
        // Description: Monitor linux processes without root permissions
        // Reference: https://github.com/DominicBreuker/pspy
        $string16 = /\/psscanner\.go/
        // Description: Monitor linux processes without root permissions
        // Reference: https://github.com/DominicBreuker/pspy
        $string17 = /\/psscanner\/psscanner\.go/
        // Description: Monitor linux processes without root permissions
        // Reference: https://github.com/DominicBreuker/pspy
        $string18 = /\[\+\]\sDropping\sinto\sshell/
        // Description: Monitor linux processes without root permissions
        // Reference: https://github.com/DominicBreuker/pspy
        $string19 = /\[\+\]\sStarting\spspy\snow/
        // Description: Monitor linux processes without root permissions
        // Reference: https://github.com/DominicBreuker/pspy
        $string20 = /\\pspy\\pspy\.go/
        // Description: Monitor linux processes without root permissions
        // Reference: https://github.com/DominicBreuker/pspy
        $string21 = /\\psscanner\\psscanner\.go/
        // Description: Monitor linux processes without root permissions
        // Reference: https://github.com/DominicBreuker/pspy
        $string22 = "3d770299898ab069e0a7f139ed0659991feeb17f73e55b398bf982932c200ef9"
        // Description: Monitor linux processes without root permissions
        // Reference: https://github.com/DominicBreuker/pspy
        $string23 = /Complete\slog\sof\spspy\s\(may\scontain\scommands\srun\sin\sthis\stest\)\:/
        // Description: Monitor linux processes without root permissions
        // Reference: https://github.com/DominicBreuker/pspy
        $string24 = "docker run -it --rm local/pspy"
        // Description: Monitor linux processes without root permissions
        // Reference: https://github.com/DominicBreuker/pspy
        $string25 = "DominicBreuker/pspy"
        // Description: Monitor linux processes without root permissions
        // Reference: https://github.com/DominicBreuker/pspy
        $string26 = "DominicBreuker/pspy"
        // Description: Monitor linux processes without root permissions
        // Reference: https://github.com/DominicBreuker/pspy
        $string27 = "pspy - version: "
        // Description: Monitor linux processes without root permissions
        // Reference: https://github.com/DominicBreuker/pspy
        $string28 = /pspy.{0,1000}psscanner/
        // Description: Monitor linux processes without root permissions
        // Reference: https://github.com/DominicBreuker/pspy
        $string29 = "pspy32 -"
        // Description: Monitor linux processes without root permissions
        // Reference: https://github.com/DominicBreuker/pspy
        $string30 = "pspy64 -"
        // Description: Monitor linux processes without root permissions
        // Reference: https://github.com/DominicBreuker/pspy
        $string31 = "pspy64 -p"
        // Description: Monitor linux processes without root permissions
        // Reference: https://github.com/DominicBreuker/pspy
        $string32 = "pspy64 -r "
        // Description: Monitor linux processes without root permissions
        // Reference: https://github.com/DominicBreuker/pspy
        $string33 = "pspy-build:latest"
        // Description: Monitor linux processes without root permissions
        // Reference: https://github.com/DominicBreuker/pspy
        $string34 = "pspy-development:latest"
        // Description: Monitor linux processes without root permissions
        // Reference: https://github.com/DominicBreuker/pspy
        $string35 = "pspy-example:latest"
        // Description: Monitor linux processes without root permissions
        // Reference: https://github.com/DominicBreuker/pspy
        $string36 = "pspy-master"
        // Description: Monitor linux processes without root permissions
        // Reference: https://github.com/DominicBreuker/pspy
        $string37 = "pspy-testing:latest"

    condition:
        any of them
}
