rule wcreddump
{
    meta:
        description = "Detection patterns for the tool 'wcreddump' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "wcreddump"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Fully automated windows credentials dumper from SAM (classic passwords) and WINHELLO (pins). Requires to be run from a linux machine with a mounted windows drive.
        // Reference: https://github.com/truerustyy/wcreddump
        $string1 = " install samdump2"
        // Description: Fully automated windows credentials dumper from SAM (classic passwords) and WINHELLO (pins). Requires to be run from a linux machine with a mounted windows drive.
        // Reference: https://github.com/truerustyy/wcreddump
        $string2 = /\swcreddump\s\(windows\scredentials\sdump\)/
        // Description: Fully automated windows credentials dumper from SAM (classic passwords) and WINHELLO (pins). Requires to be run from a linux machine with a mounted windows drive.
        // Reference: https://github.com/truerustyy/wcreddump
        $string3 = /\swcreddump\.py/
        // Description: Fully automated windows credentials dumper from SAM (classic passwords) and WINHELLO (pins). Requires to be run from a linux machine with a mounted windows drive.
        // Reference: https://github.com/truerustyy/wcreddump
        $string4 = /\sWINHELLO2hashcat\.py/
        // Description: Fully automated windows credentials dumper from SAM (classic passwords) and WINHELLO (pins). Requires to be run from a linux machine with a mounted windows drive.
        // Reference: https://github.com/truerustyy/wcreddump
        $string5 = /\/wcreddump\.git/
        // Description: Fully automated windows credentials dumper from SAM (classic passwords) and WINHELLO (pins). Requires to be run from a linux machine with a mounted windows drive.
        // Reference: https://github.com/truerustyy/wcreddump
        $string6 = /\/wcreddump\.py/
        // Description: Fully automated windows credentials dumper from SAM (classic passwords) and WINHELLO (pins). Requires to be run from a linux machine with a mounted windows drive.
        // Reference: https://github.com/truerustyy/wcreddump
        $string7 = /\/WINHELLO2hashcat\.py/
        // Description: Fully automated windows credentials dumper from SAM (classic passwords) and WINHELLO (pins). Requires to be run from a linux machine with a mounted windows drive.
        // Reference: https://github.com/truerustyy/wcreddump
        $string8 = /\\wcreddump\.py/
        // Description: Fully automated windows credentials dumper from SAM (classic passwords) and WINHELLO (pins). Requires to be run from a linux machine with a mounted windows drive.
        // Reference: https://github.com/truerustyy/wcreddump
        $string9 = /\\WINHELLO2hashcat\.py/
        // Description: Fully automated windows credentials dumper from SAM (classic passwords) and WINHELLO (pins). Requires to be run from a linux machine with a mounted windows drive.
        // Reference: https://github.com/truerustyy/wcreddump
        $string10 = "0d33356f9addc458bf9fc3861d9cafef954a51b66412b1cfc435eede351733f1"
        // Description: Fully automated windows credentials dumper from SAM (classic passwords) and WINHELLO (pins). Requires to be run from a linux machine with a mounted windows drive.
        // Reference: https://github.com/truerustyy/wcreddump
        $string11 = "samdump2 SYSTEM SAM"
        // Description: Fully automated windows credentials dumper from SAM (classic passwords) and WINHELLO (pins). Requires to be run from a linux machine with a mounted windows drive.
        // Reference: https://github.com/truerustyy/wcreddump
        $string12 = /succesfully\sdumped\sSAM\'s\shash\.es\sto\s/
        // Description: Fully automated windows credentials dumper from SAM (classic passwords) and WINHELLO (pins). Requires to be run from a linux machine with a mounted windows drive.
        // Reference: https://github.com/truerustyy/wcreddump
        $string13 = /succesfully\sdumped\sSAM\'s\shash\.es\sto\s/
        // Description: Fully automated windows credentials dumper from SAM (classic passwords) and WINHELLO (pins). Requires to be run from a linux machine with a mounted windows drive.
        // Reference: https://github.com/truerustyy/wcreddump
        $string14 = /succesfully\sdumped\sWINHELLO\spin\.s\sto\s/
        // Description: Fully automated windows credentials dumper from SAM (classic passwords) and WINHELLO (pins). Requires to be run from a linux machine with a mounted windows drive.
        // Reference: https://github.com/truerustyy/wcreddump
        $string15 = "truerustyy/wcreddump"

    condition:
        any of them
}
