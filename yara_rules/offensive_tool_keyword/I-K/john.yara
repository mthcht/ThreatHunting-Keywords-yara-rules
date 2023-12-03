rule john
{
    meta:
        description = "Detection patterns for the tool 'john' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "john"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string1 = /.{0,1000}\sbleeding\-jumbo\sjohn.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string2 = /.{0,1000}\s\-\-crack\-status.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string3 = /.{0,1000}\s\-\-format\=netntlmv2\s.{0,1000}\.txt.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string4 = /.{0,1000}\shack\.py.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string5 = /.{0,1000}\s\-inc\s\-u\=0\s.{0,1000}\.pwd.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string6 = /.{0,1000}\s\-inc\=digits\s.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string7 = /.{0,1000}\sjohn_done.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string8 = /.{0,1000}\sjohn_fork.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string9 = /.{0,1000}\sjohn_load.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string10 = /.{0,1000}\sjohn_load_conf.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string11 = /.{0,1000}\sjohn_load_conf_db.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string12 = /.{0,1000}\sjohn_log_format.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string13 = /.{0,1000}\sjohn_log_format2.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string14 = /.{0,1000}\sjohn_mpi_wait.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string15 = /.{0,1000}\sjohn_omp_fallback.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string16 = /.{0,1000}\sjohn_omp_init.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string17 = /.{0,1000}\sjohn_omp_maybe_adjust_or_fallback.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string18 = /.{0,1000}\sjohn_omp_show_info.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string19 = /.{0,1000}\sjohn_register_all.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string20 = /.{0,1000}\sjohn_register_one.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string21 = /.{0,1000}\sjohn_run.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string22 = /.{0,1000}\sjohn_set_mpi.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string23 = /.{0,1000}\sjohn_set_tristates.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string24 = /.{0,1000}\sjohn_wait.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string25 = /.{0,1000}\sJohnTheRipper\/.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string26 = /.{0,1000}\s\-\-list\=hidden\-options.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string27 = /.{0,1000}\sload_extra_pots.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string28 = /.{0,1000}\smask\?a\?a\?a\?a\?.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string29 = /.{0,1000}\s\-\-mask\=\?1\?1\?1.{0,1000}\s\-\-min\-len.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string30 = /.{0,1000}\spassword\.lst.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string31 = /.{0,1000}\srockyou\.txt\s.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string32 = /.{0,1000}\s\-\-rules:Jumbo\s.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string33 = /.{0,1000}\s\-\-session\=allrules\s\-\-wordlist.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string34 = /.{0,1000}\s\-\-show\spasswd.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string35 = /.{0,1000}\s\-\-single\sshadow\.hashes.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string36 = /.{0,1000}\s\-\-wordlist\=.{0,1000}\.lst.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string37 = /.{0,1000}\/ike\-crack\..{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string38 = /.{0,1000}\/john\s\-.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string39 = /.{0,1000}\/john\/run\/.{0,1000}\.pl.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string40 = /.{0,1000}\/john\/run\/.{0,1000}\.py.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string41 = /.{0,1000}\/JohnTheRipper.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string42 = /.{0,1000}\/netntlm\.pl.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string43 = /.{0,1000}\/pass_gen\.pl.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string44 = /.{0,1000}\/password\.lst.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string45 = /.{0,1000}\/run\/leet\.pl.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string46 = /.{0,1000}\/src\/john\.com.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string47 = /.{0,1000}\/src\/jumbo\.c.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string48 = /.{0,1000}\/src\/jumbo\.h.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string49 = /.{0,1000}\/tests\/NIST_CAVS\/.{0,1000}\.rsp.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string50 = /.{0,1000}\/unused\/locktest\.sh.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string51 = /.{0,1000}\/unused\/Yosemite\.patch.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string52 = /.{0,1000}\/word_list\.c/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string53 = /.{0,1000}\/word_list\.h/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string54 = /.{0,1000}\\password\.lst.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string55 = /.{0,1000}\\run\\john\s.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string56 = /.{0,1000}\\run\\john\\.{0,1000}\..{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string57 = /.{0,1000}\\run\\john\\.{0,1000}\.com.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string58 = /.{0,1000}\\run\\john\\.{0,1000}\.pl.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string59 = /.{0,1000}\\run\\john\\.{0,1000}\.py.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string60 = /.{0,1000}1password2john\.py.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string61 = /.{0,1000}2john\.c/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string62 = /.{0,1000}2john\.lua.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string63 = /.{0,1000}2john\.pl.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string64 = /.{0,1000}2john\.py.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string65 = /.{0,1000}7z2john\.pl.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string66 = /.{0,1000}adxcsouf2john\.py.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string67 = /.{0,1000}aem2john\.py.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string68 = /.{0,1000}aix2john\.pl.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string69 = /.{0,1000}aix2john\.py.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string70 = /.{0,1000}andotp2john\.py.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string71 = /.{0,1000}androidbackup2john\.py.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string72 = /.{0,1000}androidfde2john\.py.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string73 = /.{0,1000}ansible2john\.py.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string74 = /.{0,1000}apex2john\.py.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string75 = /.{0,1000}apop2john\.py.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string76 = /.{0,1000}applenotes2john\.py.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string77 = /.{0,1000}apt.{0,1000}\sinstall\sjohn.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string78 = /.{0,1000}aruba2john\.py.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string79 = /.{0,1000}atmail2john\.pl.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string80 = /.{0,1000}axcrypt2john\.py.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string81 = /.{0,1000}\-b\sbleeding\-jumbo.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string82 = /.{0,1000}BCHASH\-Rijndael\-128\.unverified\.test\-vectors\.txt.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string83 = /.{0,1000}BCHASH\-Rijndael\-256\.unverified\.test\-vectors\.txt.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string84 = /.{0,1000}bestcrypt2john\.py.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string85 = /.{0,1000}bestcryptve2john\.py.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string86 = /.{0,1000}bitcoin2john\.py.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string87 = /.{0,1000}bitshares2john\.py.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string88 = /.{0,1000}bitwarden2john\.py.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string89 = /.{0,1000}bks2john\.py.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string90 = /.{0,1000}blockchain2john\.py.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string91 = /.{0,1000}cardano2john\.py.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string92 = /.{0,1000}ccache2john\.py.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string93 = /.{0,1000}ccache2john\.py.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string94 = /.{0,1000}cisco2john\.pl.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string95 = /.{0,1000}coinomi2john\.py.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string96 = /.{0,1000}cracf2john\.py.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string97 = /.{0,1000}crk_get_key1.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string98 = /.{0,1000}crk_get_key2.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string99 = /.{0,1000}crk_max_keys_per_crypt.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string100 = /.{0,1000}crk_methods\..{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string101 = /.{0,1000}crk_password_loop.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string102 = /.{0,1000}dashlane2john\.py.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string103 = /.{0,1000}deepsound2john\.py.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string104 = /.{0,1000}diskcryptor2john\.py.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string105 = /.{0,1000}dmg2john\.py.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string106 = /.{0,1000}doc\/extras\/HACKING\..{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string107 = /.{0,1000}DPAPImk2john\.py.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string108 = /.{0,1000}eapmd5tojohn.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string109 = /.{0,1000}ecryptfs2john\.py.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string110 = /.{0,1000}ejabberd2john\.py.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string111 = /.{0,1000}electrum2john\.py.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string112 = /.{0,1000}encdatavault2john\.py.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string113 = /.{0,1000}encfs2john\.py.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string114 = /.{0,1000}enpass2john\.py.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string115 = /.{0,1000}enpass5tojohn\.py.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string116 = /.{0,1000}ethereum2john\.py.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string117 = /.{0,1000}fcrackzip\s.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string118 = /.{0,1000}filezilla2john\.py.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string119 = /.{0,1000}fuzz_option\.pl.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string120 = /.{0,1000}geli2john\.py.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string121 = /.{0,1000}genmkvpwd\s.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string122 = /.{0,1000}gpg2john\..{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string123 = /.{0,1000}hccapx2john\.py.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string124 = /.{0,1000}htdigest2john\.py.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string125 = /.{0,1000}http.{0,1000}\/john\/Test\/raw\/master\/.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string126 = /.{0,1000}ibmiscanner2john\.py.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string127 = /.{0,1000}ikescan2john\.py.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string128 = /.{0,1000}insert_top_100_passwords_1_G.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string129 = /.{0,1000}InsidePro\-PasswordsPro\.rule.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string130 = /.{0,1000}ios7tojohn\.pl.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string131 = /.{0,1000}itunes_backup2john\.pl.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string132 = /.{0,1000}iwork2john\.py.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string133 = /.{0,1000}john\s.{0,1000}\s\-\-incremental.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string134 = /.{0,1000}john\s.{0,1000}\s\-w\=.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string135 = /.{0,1000}john\s.{0,1000}\-groups.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string136 = /.{0,1000}john\s.{0,1000}htdigest.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string137 = /.{0,1000}john\s.{0,1000}\-inc\s.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string138 = /.{0,1000}john\s.{0,1000}\-incremental\s.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string139 = /.{0,1000}john\s.{0,1000}\-shells.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string140 = /.{0,1000}john\s.{0,1000}\-show.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string141 = /.{0,1000}john\s.{0,1000}\-single.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string142 = /.{0,1000}john\s.{0,1000}\-users.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string143 = /.{0,1000}john\s.{0,1000}\-wordlist.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string144 = /.{0,1000}john\s.{0,1000}\-\-wordlist.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string145 = /.{0,1000}john\shashes.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string146 = /.{0,1000}john\s\-\-show\s.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string147 = /.{0,1000}john\s\-\-status.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string148 = /.{0,1000}John\sthe\sRipper.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string149 = /.{0,1000}john\s\-\-wordlist.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string150 = /.{0,1000}john\.bash_completion.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string151 = /.{0,1000}john\.session\.log.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string152 = /.{0,1000}john\.zsh_completion.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string153 = /.{0,1000}john\/run\/fuzz\.dic.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string154 = /.{0,1000}john\/src\/ztex\/.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string155 = /.{0,1000}john_log_format.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string156 = /.{0,1000}john_mpi\.c.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string157 = /.{0,1000}john_register_all.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string158 = /.{0,1000}JohnTheRipper\s.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string159 = /.{0,1000}JohnTheRipper\/.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string160 = /.{0,1000}kdcdump2john\.py.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string161 = /.{0,1000}keepass_common_plug\..{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string162 = /.{0,1000}keepass2john\s.{0,1000}\.kdbx.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string163 = /.{0,1000}keychain2john\.py.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string164 = /.{0,1000}keyring2john\.py.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string165 = /.{0,1000}keystore2john\.py.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string166 = /.{0,1000}kirbi2john\..{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string167 = /.{0,1000}kirbi2john\.py.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string168 = /.{0,1000}known_hosts2john\.py.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string169 = /.{0,1000}krb2john\.py.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string170 = /.{0,1000}kwallet2john\.py.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string171 = /.{0,1000}lastpass_sniffed_fmt_plug.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string172 = /.{0,1000}lastpass2john\.py.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string173 = /.{0,1000}ldif2john\.pl.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string174 = /.{0,1000}libFuzzer\-HOWTO\..{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string175 = /.{0,1000}libreoffice2john\.py.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string176 = /.{0,1000}lion2john\.pl.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string177 = /.{0,1000}lion2john\-alt\.pl.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string178 = /.{0,1000}lotus2john\.py.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string179 = /.{0,1000}luks2john\.py.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string180 = /.{0,1000}mac2john\.py.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string181 = /.{0,1000}mac2john\-alt\.py.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string182 = /.{0,1000}mcafee_epo2john\.py.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string183 = /.{0,1000}Md4\-128\.unverified\.test\-vectors\.txt.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string184 = /.{0,1000}Md5\-128\.unverified\.test\-vectors\.txt.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string185 = /.{0,1000}monero2john\.py.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string186 = /.{0,1000}money2john\.py.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string187 = /.{0,1000}mongodb2john\.js.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string188 = /.{0,1000}mosquitto2john\.py.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string189 = /.{0,1000}mozilla2john\.py.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string190 = /.{0,1000}multibit2john\.py.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string191 = /.{0,1000}neo2john\.py.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string192 = /.{0,1000}NETLMv2_fmt_plug\..{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string193 = /.{0,1000}netntlm\.pl\s.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string194 = /.{0,1000}network2john\.lua.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string195 = /.{0,1000}office2john\.py.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string196 = /.{0,1000}openbsd_softraid2john\.py.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string197 = /.{0,1000}openssl2john\.py.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string198 = /.{0,1000}openwall\.John\.appdata\.xml.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string199 = /.{0,1000}openwall\.John\.desktop.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string200 = /.{0,1000}openwall\/john.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string201 = /.{0,1000}padlock2john\.py.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string202 = /.{0,1000}passphrase\-rule1\.rule.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string203 = /.{0,1000}passphrase\-rule2\.rule.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string204 = /.{0,1000}pcap2john\.py.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string205 = /.{0,1000}pdf2john\.pl.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string206 = /.{0,1000}pem2john\.py.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string207 = /.{0,1000}pfx2john\.py.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string208 = /.{0,1000}pgpdisk2john\.py.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string209 = /.{0,1000}pgpsda2john\.py.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string210 = /.{0,1000}pgpwde2john\.py.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string211 = /.{0,1000}pkt_comm\/word_gen\..{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string212 = /.{0,1000}pkt_comm\/word_list.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string213 = /.{0,1000}prosody2john\.py.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string214 = /.{0,1000}ps_token2john\.py.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string215 = /.{0,1000}pse2john\.py.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string216 = /.{0,1000}pwsafe2john\.py.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string217 = /.{0,1000}radius2john\.pl.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string218 = /.{0,1000}radius2john\.py.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string219 = /.{0,1000}rar2john\s.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string220 = /.{0,1000}rar2john\..{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string221 = /.{0,1000}rawSHA1_linkedIn_fmt_plug.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string222 = /.{0,1000}restic2john\.py.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string223 = /.{0,1000}Ripemd\-160\.test\-vectors\.txt.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string224 = /.{0,1000}rockyou\-30000\..{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string225 = /.{0,1000}rules\/d3ad0ne\.rule.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string226 = /.{0,1000}sap2john\.pl.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string227 = /.{0,1000}sense2john\.py.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string228 = /.{0,1000}Sha\-2\-.{0,1000}512\.unverified\.test\-vectors\.txt.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string229 = /.{0,1000}Sha\-2\-256\.unverified\.test\-vectors\.txt.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string230 = /.{0,1000}Sha\-2\-384\.unverified\.test\-vectors\.txt.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string231 = /.{0,1000}signal2john\.py.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string232 = /.{0,1000}sipdump2john\.py.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string233 = /.{0,1000}src\/cracker\..{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string234 = /.{0,1000}src\/genmkvpwd\..{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string235 = /.{0,1000}src\/john\.asm.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string236 = /.{0,1000}src\/tests\/NESSIE\/.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string237 = /.{0,1000}ssh2john\s.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string238 = /.{0,1000}ssh2john\.py.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string239 = /.{0,1000}sspr2john\.py.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string240 = /.{0,1000}staroffice2john\.py.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string241 = /.{0,1000}strip2john\.py.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string242 = /.{0,1000}T0XlCv1\.rule.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string243 = /.{0,1000}telegram2john\.py.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string244 = /.{0,1000}test_tezos2john\.py.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string245 = /.{0,1000}tezos2john\.py.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string246 = /.{0,1000}Tiger\-192\.test\-vectors\.txt.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string247 = /.{0,1000}truecrypt2john\.py.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string248 = /.{0,1000}uaf2john\..{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string249 = /.{0,1000}unshadow\s\/etc\/passwd.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string250 = /.{0,1000}unshadow\spasswd\sshadow.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string251 = /.{0,1000}vdi2john\.pl.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string252 = /.{0,1000}vmx2john\.py.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string253 = /.{0,1000}vncpcap2john\..{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string254 = /.{0,1000}Whirlpool\-Orig\-512\.verified\.test\-vectors\.txt.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string255 = /.{0,1000}Whirlpool\-Tweak\-512\.verified\.test\-vectors\.txt.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string256 = /.{0,1000}word_gen_b_varlen\..{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string257 = /.{0,1000}wpapcap2john\..{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string258 = /.{0,1000}zed2john\.py.{0,1000}/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string259 = /.{0,1000}zip2john\s.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
