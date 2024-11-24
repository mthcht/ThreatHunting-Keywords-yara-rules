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
        $string1 = " bleeding-jumbo john" nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string2 = " --crack-status" nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string3 = /\s\-\-format\=netntlmv2\s.{0,100}\.txt/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string4 = /\shack\.py/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string5 = /\s\-inc\s\-u\=0\s.{0,100}\.pwd/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string6 = " -inc=digits " nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string7 = " john_done" nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string8 = " john_fork" nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string9 = " john_load" nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string10 = " john_load_conf" nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string11 = " john_load_conf_db" nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string12 = " john_log_format" nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string13 = " john_log_format2" nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string14 = " john_mpi_wait" nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string15 = " john_omp_fallback" nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string16 = " john_omp_init" nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string17 = " john_omp_maybe_adjust_or_fallback" nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string18 = " john_omp_show_info" nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string19 = " john_register_all" nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string20 = " john_register_one" nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string21 = " john_run" nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string22 = " john_set_mpi" nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string23 = " john_set_tristates" nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string24 = " john_wait" nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string25 = " JohnTheRipper/" nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string26 = " --list=hidden-options" nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string27 = " load_extra_pots" nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string28 = /\smask\?a\?a\?a\?a\?/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string29 = /\s\-\-mask\=\?1\?1\?1.{0,100}\s\-\-min\-len/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string30 = /\spassword\.lst/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string31 = /\srockyou\.txt\s/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string32 = " --rules:Jumbo " nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string33 = " --session=allrules --wordlist" nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string34 = " --show passwd" nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string35 = /\s\-\-single\sshadow\.hashes/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string36 = /\s\-\-wordlist\=.{0,100}\.lst/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string37 = /\/ike\-crack\./ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string38 = "/john -" nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string39 = /\/john\/run\/.{0,100}\.pl/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string40 = /\/john\/run\/.{0,100}\.py/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string41 = "/JohnTheRipper" nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string42 = /\/netntlm\.pl/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string43 = /\/pass_gen\.pl/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string44 = /\/password\.lst/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string45 = /\/run\/leet\.pl/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string46 = /\/src\/john\.com/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string47 = /\/src\/jumbo\.c/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string48 = /\/src\/jumbo\.h/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string49 = /\/tests\/NIST_CAVS\/.{0,100}\.rsp/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string50 = /\/unused\/locktest\.sh/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string51 = /\/unused\/Yosemite\.patch/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string52 = /\/word_list\.c/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string53 = /\/word_list\.h/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string54 = /\\password\.lst/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string55 = /\\run\\john\s/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string56 = /\\run\\john\\.{0,100}\./ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string57 = /\\run\\john\\.{0,100}\.com/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string58 = /\\run\\john\\.{0,100}\.pl/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string59 = /\\run\\john\\.{0,100}\.py/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string60 = /1password2john\.py/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string61 = /2john\.c/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string62 = /2john\.lua/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string63 = /2john\.pl/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string64 = /2john\.py/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string65 = /7z2john\.pl/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string66 = /adxcsouf2john\.py/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string67 = /aem2john\.py/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string68 = /aix2john\.pl/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string69 = /aix2john\.py/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string70 = /andotp2john\.py/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string71 = /androidbackup2john\.py/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string72 = /androidfde2john\.py/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string73 = /ansible2john\.py/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string74 = /apex2john\.py/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string75 = /apop2john\.py/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string76 = /applenotes2john\.py/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string77 = /apt.{0,100}\sinstall\sjohn/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string78 = /aruba2john\.py/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string79 = /atmail2john\.pl/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string80 = /axcrypt2john\.py/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string81 = "-b bleeding-jumbo" nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string82 = /BCHASH\-Rijndael\-128\.unverified\.test\-vectors\.txt/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string83 = /BCHASH\-Rijndael\-256\.unverified\.test\-vectors\.txt/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string84 = /bestcrypt2john\.py/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string85 = /bestcryptve2john\.py/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string86 = /bitcoin2john\.py/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string87 = /bitshares2john\.py/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string88 = /bitwarden2john\.py/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string89 = /bks2john\.py/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string90 = /blockchain2john\.py/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string91 = /cardano2john\.py/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string92 = /ccache2john\.py/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string93 = /ccache2john\.py/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string94 = /cisco2john\.pl/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string95 = /coinomi2john\.py/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string96 = /cracf2john\.py/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string97 = "crk_get_key1" nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string98 = "crk_get_key2" nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string99 = "crk_max_keys_per_crypt" nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string100 = /crk_methods\./ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string101 = "crk_password_loop" nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string102 = /dashlane2john\.py/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string103 = /deepsound2john\.py/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string104 = /diskcryptor2john\.py/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string105 = /dmg2john\.py/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string106 = /doc\/extras\/HACKING\./ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string107 = /DPAPImk2john\.py/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string108 = "eapmd5tojohn" nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string109 = /ecryptfs2john\.py/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string110 = /ejabberd2john\.py/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string111 = /electrum2john\.py/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string112 = /encdatavault2john\.py/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string113 = /encfs2john\.py/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string114 = /enpass2john\.py/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string115 = /enpass5tojohn\.py/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string116 = /ethereum2john\.py/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string117 = "fcrackzip " nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string118 = /filezilla2john\.py/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string119 = /fuzz_option\.pl/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string120 = /geli2john\.py/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string121 = "genmkvpwd " nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string122 = /gpg2john\./ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string123 = /hccapx2john\.py/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string124 = /htdigest2john\.py/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string125 = /http.{0,100}\/john\/Test\/raw\/master\// nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string126 = /ibmiscanner2john\.py/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string127 = /ikescan2john\.py/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string128 = "insert_top_100_passwords_1_G" nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string129 = /InsidePro\-PasswordsPro\.rule/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string130 = /ios7tojohn\.pl/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string131 = /itunes_backup2john\.pl/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string132 = /iwork2john\.py/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string133 = /john\s.{0,100}\s\-\-incremental/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string134 = /john\s.{0,100}\s\-w\=/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string135 = /john\s.{0,100}\-groups/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string136 = /john\s.{0,100}htdigest/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string137 = /john\s.{0,100}\-inc\s/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string138 = /john\s.{0,100}\-incremental\s/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string139 = /john\s.{0,100}\-shells/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string140 = /john\s.{0,100}\-show/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string141 = /john\s.{0,100}\-single/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string142 = /john\s.{0,100}\-users/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string143 = /john\s.{0,100}\-wordlist/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string144 = /john\s.{0,100}\-\-wordlist/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string145 = "john hashes" nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string146 = "john --show " nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string147 = "john --status" nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string148 = "John the Ripper" nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string149 = "john --wordlist" nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string150 = /john\.bash_completion/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string151 = /john\.session\.log/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string152 = /john\.zsh_completion/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string153 = /john\/run\/fuzz\.dic/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string154 = "john/src/ztex/" nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string155 = "john_log_format" nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string156 = /john_mpi\.c/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string157 = "john_register_all" nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string158 = "JohnTheRipper " nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string159 = "JohnTheRipper/" nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string160 = /kdcdump2john\.py/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string161 = /keepass_common_plug\./ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string162 = /keepass2john\s.{0,100}\.kdbx/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string163 = /keychain2john\.py/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string164 = /keyring2john\.py/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string165 = /keystore2john\.py/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string166 = /kirbi2john\./ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string167 = /kirbi2john\.py/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string168 = /known_hosts2john\.py/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string169 = /krb2john\.py/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string170 = /kwallet2john\.py/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string171 = "lastpass_sniffed_fmt_plug" nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string172 = /lastpass2john\.py/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string173 = /ldif2john\.pl/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string174 = /libFuzzer\-HOWTO\./ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string175 = /libreoffice2john\.py/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string176 = /lion2john\.pl/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string177 = /lion2john\-alt\.pl/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string178 = /lotus2john\.py/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string179 = /luks2john\.py/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string180 = /mac2john\.py/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string181 = /mac2john\-alt\.py/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string182 = /mcafee_epo2john\.py/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string183 = /Md4\-128\.unverified\.test\-vectors\.txt/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string184 = /Md5\-128\.unverified\.test\-vectors\.txt/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string185 = /monero2john\.py/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string186 = /money2john\.py/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string187 = /mongodb2john\.js/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string188 = /mosquitto2john\.py/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string189 = /mozilla2john\.py/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string190 = /multibit2john\.py/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string191 = /neo2john\.py/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string192 = /NETLMv2_fmt_plug\./ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string193 = /netntlm\.pl\s/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string194 = /network2john\.lua/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string195 = /office2john\.py/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string196 = /openbsd_softraid2john\.py/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string197 = /openssl2john\.py/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string198 = /openwall\.John\.appdata\.xml/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string199 = /openwall\.John\.desktop/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string200 = "openwall/john" nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string201 = /padlock2john\.py/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string202 = /passphrase\-rule1\.rule/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string203 = /passphrase\-rule2\.rule/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string204 = /pcap2john\.py/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string205 = /pdf2john\.pl/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string206 = /pem2john\.py/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string207 = /pfx2john\.py/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string208 = /pgpdisk2john\.py/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string209 = /pgpsda2john\.py/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string210 = /pgpwde2john\.py/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string211 = /pkt_comm\/word_gen\./ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string212 = "pkt_comm/word_list" nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string213 = /prosody2john\.py/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string214 = /ps_token2john\.py/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string215 = /pse2john\.py/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string216 = /pwsafe2john\.py/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string217 = /radius2john\.pl/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string218 = /radius2john\.py/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string219 = "rar2john " nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string220 = /rar2john\./ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string221 = "rawSHA1_linkedIn_fmt_plug" nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string222 = /restic2john\.py/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string223 = /Ripemd\-160\.test\-vectors\.txt/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string224 = /rockyou\-30000\./ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string225 = /rules\/d3ad0ne\.rule/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string226 = /sap2john\.pl/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string227 = /sense2john\.py/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string228 = /Sha\-2\-.{0,100}512\.unverified\.test\-vectors\.txt/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string229 = /Sha\-2\-256\.unverified\.test\-vectors\.txt/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string230 = /Sha\-2\-384\.unverified\.test\-vectors\.txt/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string231 = /signal2john\.py/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string232 = /sipdump2john\.py/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string233 = /src\/cracker\./ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string234 = /src\/genmkvpwd\./ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string235 = /src\/john\.asm/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string236 = "src/tests/NESSIE/" nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string237 = "ssh2john " nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string238 = /ssh2john\.py/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string239 = /sspr2john\.py/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string240 = /staroffice2john\.py/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string241 = /strip2john\.py/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string242 = /T0XlCv1\.rule/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string243 = /telegram2john\.py/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string244 = /test_tezos2john\.py/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string245 = /tezos2john\.py/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string246 = /Tiger\-192\.test\-vectors\.txt/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string247 = /truecrypt2john\.py/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string248 = /uaf2john\./ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string249 = "unshadow /etc/passwd" nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string250 = "unshadow passwd shadow" nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string251 = /vdi2john\.pl/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string252 = /vmx2john\.py/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string253 = /vncpcap2john\./ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string254 = /Whirlpool\-Orig\-512\.verified\.test\-vectors\.txt/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string255 = /Whirlpool\-Tweak\-512\.verified\.test\-vectors\.txt/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string256 = /word_gen_b_varlen\./ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string257 = /wpapcap2john\./ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string258 = /zed2john\.py/ nocase ascii wide
        // Description: John the Ripper jumbo - advanced offline password cracker
        // Reference: https://github.com/openwall/john/
        $string259 = "zip2john " nocase ascii wide
        $metadata_regex_import = /\bimport\s+[a-zA-Z0-9_.]+\b/ nocase
        $metadata_regex_function = /function\s+[a-zA-Z_][a-zA-Z0-9_]*\(/ nocase ascii
        $metadata_regex_php = /<\?php/ nocase ascii
        $metadata_regex_createobject = /(CreateObject|WScript\.)/ nocase ascii
        $metadata_regex_script = /<script\b/ nocase ascii
        $metadata_regex_javascript = /(let\s|const\s|function\s|document\.|console\.)/ nocase ascii
        $metadata_regex_powershell = /(Write-Host|Get-[a-zA-Z]+|Invoke-|param\(|\.SYNOPSIS)/ nocase ascii
        $metadata_regex_batch = /@(echo\s|call\s|set\s|goto\s|if\s|for\s|rem\s)/ nocase ascii
        $metadata_regex_shebang = /^#!\// nocase ascii

    condition:
        ((filesize < 20MB and (
            uint16(0) == 0x5a4d or // Windows binary
            uint16(0) == 0x457f or // Linux ELF
            uint32be(0) == 0x7f454c46 or uint16(0) == 0xfeca or uint16(0) == 0xfacf or uint32(0) == 0xbebafeca or // macOS binary
            uint32(0) == 0x504B0304 or // Android APK, JAR
            uint32(0) == 0xCAFEBABE or // Java Class, Mach-O Universal Binary
            uint32(0) == 0x4D534346 or // Windows Cabinet File
            uint32(0) == 0xD0CF11E0 or // MSI Installer Package
            uint16(0) == 0x2321 or // Shebang (#!)
            uint16(0) == 0x3c3f // PHP and other script
        )) and 2 of ($string*)) or
        (filesize < 2MB and
        (
            2 of ($string*) and
            for any of ($metadata_regex_*) : ( @ <= 20000 )
        ))
}
