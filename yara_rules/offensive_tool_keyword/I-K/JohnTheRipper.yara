rule JohnTheRipper
{
    meta:
        description = "Detection patterns for the tool 'JohnTheRipper' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "JohnTheRipper"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string1 = " bleeding-jumbo john" nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string2 = " --crack-status" nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string3 = /\s\-\-format\=netntlmv2\s.{0,1000}\.txt/ nocase ascii wide
        // Description: John the Ripper is a fast password cracker.
        // Reference: https://github.com/magnumripper/JohnTheRipper
        $string4 = /\s\-\-format\=NT\s\-w\=.{0,1000}_password\.txt/
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string5 = /\shack\.py/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string6 = /\s\-inc\s\-u\=0\s.{0,1000}\.pwd/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string7 = " -inc=digits " nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string8 = " john_done" nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string9 = " john_fork" nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string10 = " john_load" nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string11 = " john_load_conf" nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string12 = " john_load_conf_db" nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string13 = " john_log_format" nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string14 = " john_log_format2" nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string15 = " john_mpi_wait" nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string16 = " john_omp_fallback" nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string17 = " john_omp_init" nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string18 = " john_omp_maybe_adjust_or_fallback" nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string19 = " john_omp_show_info" nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string20 = " john_register_all" nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string21 = " john_register_one" nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string22 = " john_run" nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string23 = " john_set_mpi" nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string24 = " john_set_tristates" nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string25 = " john_wait" nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string26 = " JohnTheRipper/" nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string27 = " --list=hidden-options" nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string28 = " load_extra_pots" nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string29 = /\smask\?a\?a\?a\?a\?/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string30 = /\s\-\-mask\=\?1\?1\?1.{0,1000}\s\-\-min\-len/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string31 = /\spassword\.lst/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string32 = /\srockyou\.txt\s/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string33 = " --rules:Jumbo " nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string34 = " --session=allrules --wordlist" nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string35 = " --show passwd"
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string36 = /\s\-\-single\sshadow\.hashes/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string37 = /\s\-\-wordlist\=.{0,1000}\.lst/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string38 = /\/ike\-crack\./ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string39 = "/john -"
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string40 = /\/john\/run\/.{0,1000}\.pl/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string41 = /\/john\/run\/.{0,1000}\.py/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string42 = "/JohnTheRipper" nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string43 = /\/netntlm\.pl/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string44 = /\/pass_gen\.pl/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string45 = /\/password\.lst/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string46 = /\/run\/leet\.pl/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string47 = /\/src\/john\.com/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string48 = /\/src\/jumbo\.c/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string49 = /\/src\/jumbo\.h/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string50 = /\/tests\/NIST_CAVS\/.{0,1000}\.rsp/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string51 = /\/unused\/locktest\.sh/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string52 = /\/unused\/Yosemite\.patch/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string53 = /\/word_list\.c/
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string54 = /\/word_list\.h/
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string55 = /\\password\.lst/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string56 = /\\run\\john\s/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string57 = /\\run\\john\\.{0,1000}\./ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string58 = /\\run\\john\\.{0,1000}\.com/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string59 = /\\run\\john\\.{0,1000}\.pl/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string60 = /\\run\\john\\.{0,1000}\.py/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string61 = /1password2john\.py/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string62 = /2john\.c/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string63 = /2john\.lua/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string64 = /2john\.pl/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string65 = /2john\.py/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string66 = /7z2john\.pl/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string67 = /adxcsouf2john\.py/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string68 = /aem2john\.py/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string69 = /aix2john\.pl/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string70 = /aix2john\.py/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string71 = /andotp2john\.py/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string72 = /androidbackup2john\.py/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string73 = /androidfde2john\.py/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string74 = /ansible2john\.py/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string75 = /apex2john\.py/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string76 = /apop2john\.py/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string77 = /applenotes2john\.py/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string78 = /apt.{0,1000}\sinstall\sjohn/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string79 = /aruba2john\.py/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string80 = /atmail2john\.pl/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string81 = /axcrypt2john\.py/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string82 = "-b bleeding-jumbo" nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string83 = /BCHASH\-Rijndael\-128\.unverified\.test\-vectors\.txt/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string84 = /BCHASH\-Rijndael\-256\.unverified\.test\-vectors\.txt/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string85 = /bestcrypt2john\.py/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string86 = /bestcryptve2john\.py/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string87 = /bitcoin2john\.py/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string88 = /bitshares2john\.py/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string89 = /bitwarden2john\.py/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string90 = /bks2john\.py/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string91 = /blockchain2john\.py/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string92 = /cardano2john\.py/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string93 = /ccache2john\.py/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string94 = /ccache2john\.py/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string95 = /cisco2john\.pl/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string96 = /coinomi2john\.py/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string97 = /cracf2john\.py/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string98 = "crk_get_key1" nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string99 = "crk_get_key2" nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string100 = "crk_max_keys_per_crypt" nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string101 = /crk_methods\./ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string102 = "crk_password_loop" nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string103 = /dashlane2john\.py/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string104 = /deepsound2john\.py/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string105 = /diskcryptor2john\.py/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string106 = /dmg2john\.py/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string107 = /doc\/extras\/HACKING\./ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string108 = /DPAPImk2john\.py/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string109 = "eapmd5tojohn" nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string110 = /ecryptfs2john\.py/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string111 = /ejabberd2john\.py/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string112 = /electrum2john\.py/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string113 = /encdatavault2john\.py/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string114 = /encfs2john\.py/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string115 = /enpass2john\.py/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string116 = /enpass5tojohn\.py/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string117 = /ethereum2john\.py/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string118 = "fcrackzip " nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string119 = /filezilla2john\.py/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string120 = /fuzz_option\.pl/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string121 = /geli2john\.py/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string122 = "genmkvpwd " nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string123 = /gpg2john\./ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string124 = /hccapx2john\.py/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string125 = /htdigest2john\.py/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string126 = /http.{0,1000}\/john\/Test\/raw\/master\// nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string127 = /ibmiscanner2john\.py/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string128 = /ikescan2john\.py/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string129 = "insert_top_100_passwords_1_G" nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string130 = /InsidePro\-PasswordsPro\.rule/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string131 = /ios7tojohn\.pl/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string132 = /itunes_backup2john\.pl/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string133 = /iwork2john\.py/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string134 = /john\s.{0,1000}\s\-\-incremental/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string135 = /john\s.{0,1000}\s\-w\=/ nocase ascii wide
        // Description: John the Ripper is a fast password cracker.
        // Reference: https://github.com/magnumripper/JohnTheRipper
        $string136 = /john\s.{0,1000}\s\-\-wordlist\=/
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string137 = /john\s.{0,1000}\-groups/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string138 = /john\s.{0,1000}htdigest/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string139 = /john\s.{0,1000}\-inc\s/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string140 = /john\s.{0,1000}\-incremental\s/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string141 = /john\s.{0,1000}\-shells/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string142 = /john\s.{0,1000}\-show/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string143 = /john\s.{0,1000}\-single/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string144 = /john\s.{0,1000}\-users/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string145 = /john\s.{0,1000}\-wordlist/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string146 = /john\s.{0,1000}\-\-wordlist/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string147 = "john hashes" nocase ascii wide
        // Description: John the Ripper is a fast password cracker.
        // Reference: https://github.com/magnumripper/JohnTheRipper
        $string148 = /john\sNTDS\.dit/
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string149 = "john --show " nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string150 = "john --status" nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string151 = "John the Ripper" nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string152 = "john --wordlist" nocase ascii wide
        // Description: John the Ripper is a fast password cracker.
        // Reference: https://github.com/magnumripper/JohnTheRipper
        $string153 = /John.{0,1000}the.{0,1000}Ripper/
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string154 = /john\.bash_completion/
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string155 = /john\.session\.log/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string156 = /john\.zsh_completion/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string157 = /john\/run\/fuzz\.dic/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string158 = "john/src/ztex/" nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string159 = "john_log_format" nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string160 = /john_mpi\.c/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string161 = "john_register_all" nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string162 = "JohnTheRipper " nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string163 = "JohnTheRipper/" nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string164 = /kdcdump2john\.py/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string165 = /keepass_common_plug\./ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string166 = /keepass2john\s.{0,1000}\.kdbx/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string167 = /keychain2john\.py/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string168 = /keyring2john\.py/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string169 = /keystore2john\.py/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string170 = /kirbi2john\./ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string171 = /kirbi2john\.py/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string172 = /known_hosts2john\.py/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string173 = /krb2john\.py/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string174 = /kwallet2john\.py/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string175 = "lastpass_sniffed_fmt_plug" nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string176 = /lastpass2john\.py/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string177 = /ldif2john\.pl/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string178 = /libFuzzer\-HOWTO\./ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string179 = /libreoffice2john\.py/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string180 = /lion2john\.pl/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string181 = /lion2john\-alt\.pl/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string182 = /lotus2john\.py/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string183 = /luks2john\.py/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string184 = /mac2john\.py/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string185 = /mac2john\-alt\.py/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string186 = /mcafee_epo2john\.py/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string187 = /Md4\-128\.unverified\.test\-vectors\.txt/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string188 = /Md5\-128\.unverified\.test\-vectors\.txt/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string189 = /monero2john\.py/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string190 = /money2john\.py/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string191 = /mongodb2john\.js/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string192 = /mosquitto2john\.py/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string193 = /mozilla2john\.py/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string194 = /multibit2john\.py/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string195 = /neo2john\.py/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string196 = /NETLMv2_fmt_plug\./ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string197 = /netntlm\.pl\s/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string198 = /network2john\.lua/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string199 = /office2john\.py/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string200 = /openbsd_softraid2john\.py/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string201 = /openssl2john\.py/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string202 = /openwall\.John\.appdata\.xml/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string203 = /openwall\.John\.desktop/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string204 = "openwall/john" nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string205 = /padlock2john\.py/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string206 = /passphrase\-rule1\.rule/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string207 = /passphrase\-rule2\.rule/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string208 = /pcap2john\.py/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string209 = /pdf2john\.pl/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string210 = /pem2john\.py/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string211 = /pfx2john\.py/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string212 = /pgpdisk2john\.py/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string213 = /pgpsda2john\.py/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string214 = /pgpwde2john\.py/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string215 = /pkt_comm\/word_gen\./ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string216 = "pkt_comm/word_list" nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string217 = /prosody2john\.py/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string218 = /ps_token2john\.py/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string219 = /pse2john\.py/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string220 = /pwsafe2john\.py/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string221 = /radius2john\.pl/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string222 = /radius2john\.py/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string223 = "rar2john " nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string224 = /rar2john\./ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string225 = "rawSHA1_linkedIn_fmt_plug" nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string226 = /restic2john\.py/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string227 = /Ripemd\-160\.test\-vectors\.txt/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string228 = /rockyou\-30000\./ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string229 = /rules\/d3ad0ne\.rule/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string230 = /sap2john\.pl/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string231 = /sense2john\.py/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string232 = /Sha\-2\-.{0,1000}512\.unverified\.test\-vectors\.txt/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string233 = /Sha\-2\-256\.unverified\.test\-vectors\.txt/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string234 = /Sha\-2\-384\.unverified\.test\-vectors\.txt/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string235 = /signal2john\.py/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string236 = /sipdump2john\.py/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string237 = /src\/cracker\./ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string238 = /src\/genmkvpwd\./ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string239 = /src\/john\.asm/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string240 = "src/tests/NESSIE/" nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string241 = "ssh2john " nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string242 = /ssh2john\.py/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string243 = /sspr2john\.py/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string244 = /staroffice2john\.py/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string245 = /strip2john\.py/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string246 = /T0XlCv1\.rule/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string247 = /telegram2john\.py/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string248 = /test_tezos2john\.py/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string249 = /tezos2john\.py/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string250 = /Tiger\-192\.test\-vectors\.txt/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string251 = /truecrypt2john\.py/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string252 = /uaf2john\./ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string253 = "unshadow /etc/passwd"
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string254 = "unshadow passwd shadow"
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string255 = /vdi2john\.pl/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string256 = /vmx2john\.py/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string257 = /vncpcap2john\./ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string258 = /Whirlpool\-Orig\-512\.verified\.test\-vectors\.txt/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string259 = /Whirlpool\-Tweak\-512\.verified\.test\-vectors\.txt/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string260 = /word_gen_b_varlen\./ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string261 = /wpapcap2john\./ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string262 = /zed2john\.py/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string263 = "zip2john " nocase ascii wide

    condition:
        any of them
}
