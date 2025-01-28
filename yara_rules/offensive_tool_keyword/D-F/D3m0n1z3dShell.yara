rule D3m0n1z3dShell
{
    meta:
        description = "Detection patterns for the tool 'D3m0n1z3dShell' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "D3m0n1z3dShell"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Demonized Shell is an Advanced Tool for persistence in linux
        // Reference: https://github.com/MatheuZSecurity/D3m0n1z3dShell
        $string1 = /\.bashrc\spersistence\ssetup\ssuccessfully/
        // Description: Demonized Shell is an Advanced Tool for persistence in linux
        // Reference: https://github.com/MatheuZSecurity/D3m0n1z3dShell
        $string2 = "/chisel_x32"
        // Description: Demonized Shell is an Advanced Tool for persistence in linux
        // Reference: https://github.com/MatheuZSecurity/D3m0n1z3dShell
        $string3 = "/chisel_x64"
        // Description: Demonized Shell is an Advanced Tool for persistence in linux
        // Reference: https://github.com/MatheuZSecurity/D3m0n1z3dShell
        $string4 = /\/D3m0n1z3dShell\.git/
        // Description: Demonized Shell is an Advanced Tool for persistence in linux
        // Reference: https://github.com/MatheuZSecurity/D3m0n1z3dShell
        $string5 = "/D3m0n1z3dShell/archive/"
        // Description: Demonized Shell is an Advanced Tool for persistence in linux
        // Reference: https://github.com/MatheuZSecurity/D3m0n1z3dShell
        $string6 = /\/deepce\.sh/
        // Description: Demonized Shell is an Advanced Tool for persistence in linux
        // Reference: https://github.com/MatheuZSecurity/D3m0n1z3dShell
        $string7 = /\/install_locutus\.sh/
        // Description: Demonized Shell is an Advanced Tool for persistence in linux
        // Reference: https://github.com/MatheuZSecurity/D3m0n1z3dShell
        $string8 = /\/linpeas\.sh/
        // Description: Demonized Shell is an Advanced Tool for persistence in linux
        // Reference: https://github.com/MatheuZSecurity/D3m0n1z3dShell
        $string9 = "/tmp/borg_d3monized"
        // Description: Demonized Shell is an Advanced Tool for persistence in linux
        // Reference: https://github.com/MatheuZSecurity/D3m0n1z3dShell
        $string10 = /\/tmp\/tmpfolder\/pingoor\.c/
        // Description: Demonized Shell is an Advanced Tool for persistence in linux
        // Reference: https://github.com/MatheuZSecurity/D3m0n1z3dShell
        $string11 = /\/tmp\/tmpfolder\/pingoor\.h/
        // Description: Demonized Shell is an Advanced Tool for persistence in linux
        // Reference: https://github.com/MatheuZSecurity/D3m0n1z3dShell
        $string12 = /\[D3m0niz3d\]\~\#/
        // Description: Demonized Shell is an Advanced Tool for persistence in linux
        // Reference: https://github.com/MatheuZSecurity/D3m0n1z3dShell
        $string13 = /\\chisel_x32/
        // Description: Demonized Shell is an Advanced Tool for persistence in linux
        // Reference: https://github.com/MatheuZSecurity/D3m0n1z3dShell
        $string14 = /\\chisel_x64/
        // Description: Demonized Shell is an Advanced Tool for persistence in linux
        // Reference: https://github.com/MatheuZSecurity/D3m0n1z3dShell
        $string15 = "addPreloadToPrivesc"
        // Description: Demonized Shell is an Advanced Tool for persistence in linux
        // Reference: https://github.com/MatheuZSecurity/D3m0n1z3dShell
        $string16 = "bashRCPersistence"
        // Description: Demonized Shell is an Advanced Tool for persistence in linux
        // Reference: https://github.com/MatheuZSecurity/D3m0n1z3dShell
        $string17 = "D3m0n1z3dShell-main"
        // Description: Demonized Shell is an Advanced Tool for persistence in linux
        // Reference: https://github.com/MatheuZSecurity/D3m0n1z3dShell
        $string18 = /deepce\.sh\s\-e\s/
        // Description: Demonized Shell is an Advanced Tool for persistence in linux
        // Reference: https://github.com/MatheuZSecurity/D3m0n1z3dShell
        $string19 = /demonizedshell\.sh/
        // Description: Demonized Shell is an Advanced Tool for persistence in linux
        // Reference: https://github.com/MatheuZSecurity/D3m0n1z3dShell
        $string20 = /demonizedshell_static\.sh/
        // Description: Demonized Shell is an Advanced Tool for persistence in linux
        // Reference: https://github.com/MatheuZSecurity/D3m0n1z3dShell
        $string21 = "discovery_port_scan"
        // Description: Demonized Shell is an Advanced Tool for persistence in linux
        // Reference: https://github.com/MatheuZSecurity/D3m0n1z3dShell
        $string22 = /dumpcreds.{0,1000}mimipenguin/
        // Description: Demonized Shell is an Advanced Tool for persistence in linux
        // Reference: https://github.com/MatheuZSecurity/D3m0n1z3dShell
        $string23 = "I2lmbmRlZiBQSU5HT09SCiNkZWZpbmUgUElOR09PUgoKI2RlZmluZSBTRVJWRVJJUCAiM"
        // Description: Demonized Shell is an Advanced Tool for persistence in linux
        // Reference: https://github.com/MatheuZSecurity/D3m0n1z3dShell
        $string24 = "icmpBackdoor"
        // Description: Demonized Shell is an Advanced Tool for persistence in linux
        // Reference: https://github.com/MatheuZSecurity/D3m0n1z3dShell
        $string25 = /implant_rootkit\.sh/
        // Description: Demonized Shell is an Advanced Tool for persistence in linux
        // Reference: https://github.com/MatheuZSecurity/D3m0n1z3dShell
        $string26 = "lkmRootkitmodified"
        // Description: Demonized Shell is an Advanced Tool for persistence in linux
        // Reference: https://github.com/MatheuZSecurity/D3m0n1z3dShell
        $string27 = "MatheuZSecurity/D3m0n1z3dShell"
        // Description: Demonized Shell is an Advanced Tool for persistence in linux
        // Reference: https://github.com/MatheuZSecurity/D3m0n1z3dShell
        $string28 = /mimipenguin\.py/
        // Description: Demonized Shell is an Advanced Tool for persistence in linux
        // Reference: https://github.com/MatheuZSecurity/D3m0n1z3dShell
        $string29 = /mimipenguin\.sh/
        // Description: Demonized Shell is an Advanced Tool for persistence in linux
        // Reference: https://github.com/MatheuZSecurity/D3m0n1z3dShell
        $string30 = "MotdPersistence"
        // Description: Demonized Shell is an Advanced Tool for persistence in linux
        // Reference: https://github.com/MatheuZSecurity/D3m0n1z3dShell
        $string31 = /pwd\|passwd\|password\|PASSWD\|PASSWORD\|dbuser\|dbpass\|pass/
        // Description: Demonized Shell is an Advanced Tool for persistence in linux
        // Reference: https://github.com/MatheuZSecurity/D3m0n1z3dShell
        $string32 = "su_brute_user_num"

    condition:
        any of them
}
