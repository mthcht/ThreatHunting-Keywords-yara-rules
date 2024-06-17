rule chntpw
{
    meta:
        description = "Detection patterns for the tool 'chntpw' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "chntpw"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: reset a password on your system
        // Reference: https://pogostick.net/~pnh/ntpasswd/chntpw-source-140201.zip
        $string1 = /\sinstall\schntpw/ nocase ascii wide
        // Description: reset a password on your system
        // Reference: https://pogostick.net/~pnh/ntpasswd/chntpw-source-140201.zip
        $string2 = /\ssam_reset_all_pw\(/ nocase ascii wide
        // Description: reset a password on your system
        // Reference: https://pogostick.net/~pnh/ntpasswd/chntpw-source-140201.zip
        $string3 = /\/chntpw\s\-/ nocase ascii wide
        // Description: reset a password on your system
        // Reference: https://pogostick.net/~pnh/ntpasswd/chntpw-source-140201.zip
        $string4 = /\/chntpw\-140201/ nocase ascii wide
        // Description: reset a password on your system
        // Reference: https://pogostick.net/~pnh/ntpasswd/chntpw-source-140201.zip
        $string5 = /\/sampasswd/ nocase ascii wide
        // Description: reset a password on your system
        // Reference: https://pogostick.net/~pnh/ntpasswd/chntpw-source-140201.zip
        $string6 = /\/samusrgrp\./ nocase ascii wide
        // Description: reset a password on your system
        // Reference: https://pogostick.net/~pnh/ntpasswd/chntpw-source-140201.zip
        $string7 = /\/sbin\/chntpw/ nocase ascii wide
        // Description: reset a password on your system
        // Reference: https://pogostick.net/~pnh/ntpasswd/chntpw-source-140201.zip
        $string8 = /\/sbin\/sampasswd/ nocase ascii wide
        // Description: reset a password on your system
        // Reference: https://pogostick.net/~pnh/ntpasswd/chntpw-source-140201.zip
        $string9 = /\/sbin\/samunlock/ nocase ascii wide
        // Description: reset a password on your system
        // Reference: https://pogostick.net/~pnh/ntpasswd/chntpw-source-140201.zip
        $string10 = /\/sbin\/samusrgrp/ nocase ascii wide
        // Description: reset a password on your system
        // Reference: https://pogostick.net/~pnh/ntpasswd/chntpw-source-140201.zip
        $string11 = /\/usb140201\.zip/ nocase ascii wide
        // Description: reset a password on your system
        // Reference: https://pogostick.net/~pnh/ntpasswd/chntpw-source-140201.zip
        $string12 = /\/usr\/share\/doc\/chntpw/ nocase ascii wide
        // Description: reset a password on your system
        // Reference: https://pogostick.net/~pnh/ntpasswd/chntpw-source-140201.zip
        $string13 = /\\chntpw\.c/ nocase ascii wide
        // Description: reset a password on your system
        // Reference: https://pogostick.net/~pnh/ntpasswd/chntpw-source-140201.zip
        $string14 = /\\chntpw\-140201/ nocase ascii wide
        // Description: reset a password on your system
        // Reference: https://pogostick.net/~pnh/ntpasswd/chntpw-source-140201.zip
        $string15 = /\\sampasswd\./ nocase ascii wide
        // Description: reset a password on your system
        // Reference: https://pogostick.net/~pnh/ntpasswd/chntpw-source-140201.zip
        $string16 = /\>\schntpw\sMain\sInteractive\sMenu\s\</ nocase ascii wide
        // Description: reset a password on your system
        // Reference: https://pogostick.net/~pnh/ntpasswd/chntpw-source-140201.zip
        $string17 = /\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\>\sSYSKEY\sCHECK\s\<\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-/ nocase ascii wide
        // Description: reset a password on your system
        // Reference: https://pogostick.net/~pnh/ntpasswd/chntpw-source-140201.zip
        $string18 = /0bb60287c127bcef5b7018b3b692eb7a91dab1a034fa65780b5e14333a63f62b/ nocase ascii wide
        // Description: reset a password on your system
        // Reference: https://pogostick.net/~pnh/ntpasswd/chntpw-source-140201.zip
        $string19 = /1083596da1857862551870eb6fd06c26bdd2cac7698b27034f6cc8d773a3664b/ nocase ascii wide
        // Description: reset a password on your system
        // Reference: https://pogostick.net/~pnh/ntpasswd/chntpw-source-140201.zip
        $string20 = /2acfc293585568970aa8ea676822e0c905d4eec4c0f8c743f58ce1b099dbe29d/ nocase ascii wide
        // Description: reset a password on your system
        // Reference: https://pogostick.net/~pnh/ntpasswd/chntpw-source-140201.zip
        $string21 = /555009ba8f9b57011fef7ca143c78e15d11bce2e471f6b742cbddda5c2d12e60/ nocase ascii wide
        // Description: reset a password on your system
        // Reference: https://pogostick.net/~pnh/ntpasswd/chntpw-source-140201.zip
        $string22 = /c88d86aee55b31827ab4782d05bd44922276955909c43c69f0fb15377cc64374/ nocase ascii wide
        // Description: reset a password on your system
        // Reference: https://pogostick.net/~pnh/ntpasswd/chntpw-source-140201.zip
        $string23 = /c9598fe89c9f4ca470ce47b556fea6289b05b1850c629c2c2f51f2efc995247c/ nocase ascii wide
        // Description: reset a password on your system
        // Reference: https://pogostick.net/~pnh/ntpasswd/chntpw-source-140201.zip
        $string24 = /chntpw\sEdit\sUser\sInfo\s\&\sPasswords/ nocase ascii wide
        // Description: reset a password on your system
        // Reference: https://pogostick.net/~pnh/ntpasswd/chntpw-source-140201.zip
        $string25 = /chntpw\.com\/download/ nocase ascii wide
        // Description: reset a password on your system
        // Reference: https://pogostick.net/~pnh/ntpasswd/chntpw-source-140201.zip
        $string26 = /chntpw\.static/ nocase ascii wide
        // Description: reset a password on your system
        // Reference: https://pogostick.net/~pnh/ntpasswd/chntpw-source-140201.zip
        $string27 = /Failed\slogins\sbefore\slockout\sis\:\s.{0,1000}max_sam_lock/ nocase ascii wide
        // Description: reset a password on your system
        // Reference: https://pogostick.net/~pnh/ntpasswd/chntpw-source-140201.zip
        $string28 = /LANMAN\spassword\sIS\showever\sset\.\sWill\snow\sinstall\snew\spassword\sas\sNT\spass\sinstead/ nocase ascii wide
        // Description: reset a password on your system
        // Reference: https://pogostick.net/~pnh/ntpasswd/chntpw-source-140201.zip
        $string29 = /pkgs\.org\/download\/chntpw/ nocase ascii wide
        // Description: reset a password on your system
        // Reference: https://pogostick.net/~pnh/ntpasswd/chntpw-source-140201.zip
        $string30 = /pogostick\.net\/\~pnh\/ntpasswd\// nocase ascii wide
        // Description: reset a password on your system
        // Reference: https://pogostick.net/~pnh/ntpasswd/chntpw-source-140201.zip
        $string31 = /sampasswd\s\-/ nocase ascii wide
        // Description: reset a password on your system
        // Reference: https://pogostick.net/~pnh/ntpasswd/chntpw-source-140201.zip
        $string32 = /samunlock\s\-/ nocase ascii wide
        // Description: reset a password on your system
        // Reference: https://pogostick.net/~pnh/ntpasswd/chntpw-source-140201.zip
        $string33 = /samusrgrp\s\-a\s/ nocase ascii wide
        // Description: reset a password on your system
        // Reference: https://pogostick.net/~pnh/ntpasswd/chntpw-source-140201.zip
        $string34 = /samusrgrp\s\-r\s/ nocase ascii wide
        // Description: reset a password on your system
        // Reference: https://pogostick.net/~pnh/ntpasswd/chntpw-source-140201.zip
        $string35 = /SYSKEY\sRESET\!\\nNow\splease\sset\snew\sadministrator\spassword\!/ nocase ascii wide
        // Description: reset a password on your system
        // Reference: https://pogostick.net/~pnh/ntpasswd/chntpw-source-140201.zip
        $string36 = /Will\sadd\sthe\suser\sto\sthe\sadministrator\sgroup\s\(0x220\)/ nocase ascii wide

    condition:
        any of them
}
