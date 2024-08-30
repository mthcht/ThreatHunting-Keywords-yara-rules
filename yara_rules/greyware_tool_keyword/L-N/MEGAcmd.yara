rule MEGAcmd
{
    meta:
        description = "Detection patterns for the tool 'MEGAcmd' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "MEGAcmd"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string1 = /\sMEGAcmd\.sh/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string2 = /\$\(mega\-whoami\)/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string3 = /\$MEGACMDSHELL/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string4 = /\%LOCALAPPDATA\%\\MEGAcmd/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string5 = /\/apache\-megacmd\.conf/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string6 = /\/Applications\/MEGAcmd\.app/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string7 = /\/MEGAclient\.exe/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string8 = /\/MEGAcmd\.exe/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string9 = /\/MEGAcmd\.sh/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string10 = /\/MEGAcmdServer\.exe/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string11 = /\/MEGAcmdSetup\.exe/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string12 = /\/MEGAcmdSetup32\.exe/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string13 = /\/MEGAcmdSetup64\.exe/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string14 = /\/MEGAcmdSetup64\.exe/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string15 = /\/MEGAcmdShell\.exe/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string16 = /\/MEGAcmdUpdater\.app/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string17 = /\/QNAP_NAS\/megacmdpkg/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string18 = /\/upd\/mcmd\/MEGAcmd\.app/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string19 = /\/usr\/bin\/mega\-attr/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string20 = /\/usr\/bin\/mega\-backup/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string21 = /\/usr\/bin\/mega\-cancel/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string22 = /\/usr\/bin\/mega\-cat/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string23 = /\/usr\/bin\/mega\-cd/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string24 = /\/usr\/bin\/mega\-cmd/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string25 = /\/usr\/bin\/mega\-cmd/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string26 = /\/usr\/bin\/mega\-cmd\-server/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string27 = /\/usr\/bin\/mega\-confirm/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string28 = /\/usr\/bin\/mega\-confirmcancel/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string29 = /\/usr\/bin\/mega\-cp/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string30 = /\/usr\/bin\/mega\-debug/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string31 = /\/usr\/bin\/mega\-deleteversions/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string32 = /\/usr\/bin\/mega\-df/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string33 = /\/usr\/bin\/mega\-du/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string34 = /\/usr\/bin\/mega\-errorcode/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string35 = /\/usr\/bin\/mega\-exclude/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string36 = /\/usr\/bin\/mega\-exec/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string37 = /\/usr\/bin\/mega\-export/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string38 = /\/usr\/bin\/mega\-find/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string39 = /\/usr\/bin\/mega\-ftp/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string40 = /\/usr\/bin\/mega\-get/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string41 = /\/usr\/bin\/mega\-graphics/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string42 = /\/usr\/bin\/mega\-help/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string43 = /\/usr\/bin\/mega\-https/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string44 = /\/usr\/bin\/mega\-import/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string45 = /\/usr\/bin\/mega\-invite/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string46 = /\/usr\/bin\/mega\-ipc/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string47 = /\/usr\/bin\/mega\-killsession/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string48 = /\/usr\/bin\/mega\-lcd/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string49 = /\/usr\/bin\/mega\-log/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string50 = /\/usr\/bin\/mega\-login/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string51 = /\/usr\/bin\/mega\-logout/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string52 = /\/usr\/bin\/mega\-lpwd/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string53 = /\/usr\/bin\/mega\-ls/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string54 = /\/usr\/bin\/mega\-mediainfo/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string55 = /\/usr\/bin\/mega\-mkdir/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string56 = /\/usr\/bin\/mega\-mount/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string57 = /\/usr\/bin\/mega\-mv/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string58 = /\/usr\/bin\/mega\-passwd/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string59 = /\/usr\/bin\/mega\-permissions/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string60 = /\/usr\/bin\/mega\-preview/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string61 = /\/usr\/bin\/mega\-proxy/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string62 = /\/usr\/bin\/mega\-put/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string63 = /\/usr\/bin\/mega\-pwd/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string64 = /\/usr\/bin\/mega\-quit/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string65 = /\/usr\/bin\/mega\-reload/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string66 = /\/usr\/bin\/mega\-rm/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string67 = /\/usr\/bin\/mega\-session/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string68 = /\/usr\/bin\/mega\-share/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string69 = /\/usr\/bin\/mega\-showpcr/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string70 = /\/usr\/bin\/mega\-signup/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string71 = /\/usr\/bin\/mega\-speedlimit/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string72 = /\/usr\/bin\/mega\-sync/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string73 = /\/usr\/bin\/mega\-thumbnail/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string74 = /\/usr\/bin\/mega\-transfers/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string75 = /\/usr\/bin\/mega\-tree/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string76 = /\/usr\/bin\/mega\-userattr/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string77 = /\/usr\/bin\/mega\-users/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string78 = /\/usr\/bin\/mega\-version/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string79 = /\/usr\/bin\/mega\-webdav/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string80 = /\/usr\/bin\/mega\-whoami/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string81 = /\/usr\/share\/doc\/megacmd\// nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string82 = /\\\\\.\\\\pipe\\\\megacmdpipe_/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string83 = /\\AppData\\Local\\MEGAcmd/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string84 = /\\CurrentVersion\\Uninstall\\MEGAcmd\\/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string85 = /\\mega\-attr\.bat/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string86 = /\\mega\-backup\.bat/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string87 = /\\mega\-cancel\.bat/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string88 = /\\mega\-cat\.bat/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string89 = /\\mega\-cd\.bat/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string90 = /\\MEGAclient\.exe/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string91 = /\\MEGAcmd\.exe/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string92 = /\\MEGAcmd\.lnk/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string93 = /\\megacmdpipe_/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string94 = /\\MEGAcmdServer\.exe/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string95 = /\\MEGAcmdSetup\.exe/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string96 = /\\MEGAcmdSetup32\.exe/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string97 = /\\MEGAcmdSetup64\.exe/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string98 = /\\MEGAcmdSetup64\.exe/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string99 = /\\MEGAcmdShell\.exe/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string100 = /\\MEGAcmdUpdater\.exe/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string101 = /\\mega\-confirm\.bat/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string102 = /\\mega\-confirmcancel\.bat/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string103 = /\\mega\-cp\.bat/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string104 = /\\mega\-debug\.bat/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string105 = /\\mega\-deleteversions\.bat/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string106 = /\\mega\-df\.bat/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string107 = /\\mega\-du\.bat/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string108 = /\\mega\-errorcode\.bat/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string109 = /\\mega\-exclude\.bat/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string110 = /\\mega\-export\.bat/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string111 = /\\mega\-find\.bat/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string112 = /\\mega\-ftp\.bat/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string113 = /\\mega\-get\.bat/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string114 = /\\mega\-graphics\.bat/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string115 = /\\mega\-help\.bat/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string116 = /\\mega\-https\.bat/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string117 = /\\mega\-import\.bat/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string118 = /\\mega\-invite\.bat/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string119 = /\\mega\-ipc\.bat/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string120 = /\\mega\-killsession\.bat/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string121 = /\\mega\-lcd\.bat/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string122 = /\\mega\-log\.bat/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string123 = /\\mega\-login\.bat/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string124 = /\\mega\-logout\.bat/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string125 = /\\mega\-lpwd\.bat/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string126 = /\\mega\-lpwd\.bat/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string127 = /\\mega\-ls\.bat/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string128 = /\\mega\-mediainfo\.bat/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string129 = /\\mega\-mkdir\.bat/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string130 = /\\mega\-mount\.bat/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string131 = /\\mega\-mv\.bat/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string132 = /\\mega\-passwd\.bat/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string133 = /\\mega\-preview\.bat/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string134 = /\\mega\-proxy\.bat/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string135 = /\\mega\-put\.bat/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string136 = /\\mega\-pwd\.bat/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string137 = /\\mega\-pwd\.bat/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string138 = /\\mega\-quit\.bat/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string139 = /\\mega\-reload\.bat/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string140 = /\\mega\-rm\.bat/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string141 = /\\mega\-session\.bat/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string142 = /\\mega\-share\.bat/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string143 = /\\mega\-showpcr\.bat/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string144 = /\\mega\-signup\.bat/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string145 = /\\mega\-speedlimit\.bat/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string146 = /\\mega\-sync\.bat/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string147 = /\\mega\-thumbnail\.bat/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string148 = /\\mega\-transfers\.bat/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string149 = /\\mega\-tree\.bat/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string150 = /\\mega\-userattr\.bat/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string151 = /\\mega\-users\.bat/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string152 = /\\mega\-version\.bat/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string153 = /\\mega\-webdav\.bat/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string154 = /\\mega\-whoami\.bat/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string155 = /\\Update\sMEGAcmd\.lnk/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string156 = /\>MEGAcmd\</ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string157 = /0302bf02c300acfcfcacc660b0bc9fb2077c1fdddc70d07196c72ffce08fe57a/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string158 = /03d39664173b9baf2ae530b457510c4ee915e9060be46063511ed903d3afa265/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string159 = /04fe985dcc18c3ab8dc4ecf5ebf61ed9dd4bafdcd0937c8d10235c98b2f4a9ae/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string160 = /05a360775b320890751946115dc6802fb3281817088c98696df97015abb5207a/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string161 = /071c731ba00d290f45bb8c1b53bb18f27ea8ac9780e9fa30e66cb071ae743778/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string162 = /074be5bde2acec1ea578d7c8e56463ff115851c9af70caeef002ae13c2cee1a3/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string163 = /07f035eece5daa843a0b570b66d714e35f886e21a05446454743ed6e4729fc16/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string164 = /0809a44b710a9ff83ae4ab0358fa49881955184ca2d8823b2a1713d2a5d3f741/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string165 = /081bc7643ef925369e6a552549d998bdf92d15a9d0e1239a2502fadfe30dcd44/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string166 = /0db350f810a9f99c15d47e7c8d5588443952e00c0a49f88a6ffa776250b03a08/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string167 = /0e683610f7369c674cebc1ecf8d6e030f0433226887b902e74fe1e174c23a6a7/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string168 = /0f5947f5dbd2543c49853451d6d0deb64b04796e4c61327a1b5aa1c295b2a861/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string169 = /136759cb34240eab13e8251300ad1ebcf5e3d3f9c1f4fdd0ad01e71747f81431/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string170 = /1489daf3d466bd60c6b175e66bb567396b95e269bedaa42c4516392c49028f06/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string171 = /167d72cbaa49b8c6c54d57ab44ad9e907f4bf9551460574f4231a9dd956c4c32/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string172 = /1e55e2b5357bce9f5fa54d2a12801dfba6c70262a6ddceae4b227a014db0aa92/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string173 = /20c963d0749b58afccdb7d45ff36451015689bec1c035ee7bf809c7ee5b6b483/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string174 = /233717710c3ac45906e2cbd110a167d7779bd6697a508013c5b6559bbce97815/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string175 = /24d85b5700f05d7b638d294c87e8b8809df80f0611c63ee818f60ed487f1b4bc/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string176 = /2cc646024fa74ade8763e8e9d030eaab511fb96b4c6cbac1059beae4e7654cb6/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string177 = /2d98d3ea74419cd604113a4ccf8a360ebf31d8da740219c4c1f426cfe13afe5b/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string178 = /2ff46b2628610c91de2378a820fc1290e40c1d28029da8609a338ba7efe2a684/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string179 = /30612705f43fb5234efab3db8ec78568c8392cdf652cd5b7ef95c31a1876c670/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string180 = /30fe5d62f0f47418dc83e03bc80977426010c8edcf01e4e7db820965e2781442/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string181 = /319a1fbefb63c3be58dcf357864f13ff21c664f0c15e535ac87723955e7826b1/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string182 = /36a3dedaed8d89acb2703ab54c0f7ded489a1210b8e21935e970bddd3115e87c/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string183 = /383f712ce7d07385f41a48f0965db96ac74bea74e7eae0c297d973ad5a9be620/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string184 = /38744af426f8304c5ee9c2857291225726bffe2788870f2cb9e6a3b8836297e6/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string185 = /38744af426f8304c5ee9c2857291225726bffe2788870f2cb9e6a3b8836297e6/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string186 = /3d74803de0136e858f96678e1cdea410256fbf34fc83c54edd204d186ecd412e/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string187 = /3e1b11f8d4839e0d7f09b7cc27a6d10a82b5944512a59dfa9192603f28b50baf/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string188 = /44026a4ab85bb59d02241e400848ac77be17c60fc86a0d07055e8ed8fe490ba2/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string189 = /4a0231a6f5ccb7f5908a9d7f12987efa1b45ff2148214360b4a205f15e77075f/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string190 = /4c77daadff57f64045bb324c78424a543c7703055d8e1827862e8b9920d541de/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string191 = /4d4ca15944e2f75e8b86ee2bf92c458a40ed625bdc71e6d7d24d218c370c595b/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string192 = /4e694c7eb85dcf55d7642f3504a5d63493e46ebd711735c57a45569ef2a7b88a/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string193 = /4e703495f3616dd936afdfa2c32958189ae5e90328d9389b86e49a50654e6393/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string194 = /4f3adf3695bebc9fbe10e01ab17ac24f71b146ace019a808aba29f8e8ffdecb8/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string195 = /551acd5364dcb82cadc68a6b1dd317b182fd797c0d6f170ce2ca922ad293fd1d/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string196 = /567d6614d077fa3fb569dd7a3d8fec5c0b3f6b09b0f82528f55337c637e76652/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string197 = /58574690db6cfff0ffa7864a0a13265ae1bd37d5fc3b0d9e0c88a1f7d69c193d/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string198 = /59606376cabc50a19af3732cddbbcda40c59e0c85aa6bc0320420a6a19abca49/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string199 = /5c3128dfd3f4d604afa6e602aca4a346d758d889400eb74584c88f1e40fe9bac/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string200 = /5c3e73cd1ce2876596cad9dccb83f6243d0d6720b1059a663a36b084be5108d3/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string201 = /5e71e62bfed96e5af56135c13f5e0c8ea26e589f8a7b74838d346954455cbbe0/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string202 = /5e7d3bce04b582aea59098cb2b11082a63d900c521775d962528564d258f7110/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string203 = /61482ef4ebfebd390cc8409ac09b486c61bc71295cdda882e1f9b5b3cd1cea4d/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string204 = /6364d746c3f1f0329fd67cec0f6a1f09ae3e521f3ef37b0ab728009cf55c4a5c/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string205 = /6364d746c3f1f0329fd67cec0f6a1f09ae3e521f3ef37b0ab728009cf55c4a5c/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string206 = /63916d22e904aeae13bc1fb08cc8a6f3f2e165fbf63f348dacdd6acffb780491/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string207 = /6678de2dac73cd8adb8e56721871afdee864f06aaf43fb1f854ea793148defd4/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string208 = /66a2764e71b7eed7243032dd66476e7aa59d9f4667005d8a4190197667fee9b5/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string209 = /66fc8fa5564448729b569b843c158d933d8774666651f98cfbd757ea9d721d94/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string210 = /690c56c5ebd58d596632a4ff28596df8aa478309fc979b9eb8b07fb89db4d944/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string211 = /6c20c6297aa22f6d3dcc00987a03ee30d2aff9051ba85832a6e20c3780bc599d/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string212 = /6c2523493b48a91d2e484224c86431fddbbfb549d242a52182282ef8077341ae/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string213 = /6f0a3e80dcde8611beb4ac1d9e575601997e58b9a4a17054c5cb4eedf6f8062f/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string214 = /6f35a34033499938700e42f4123399f711003d2dab83ed50e69f7df5ecf976d8/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string215 = /6f54f9c1108613f68114da87cba5fc1c4a800d62fcfaf42d8b3cbb76436f5cb6/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string216 = /75c997df094171b145b07be980e5812a4c853d8c5e0a6d465a3d5b924af7c23e/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string217 = /772500800e1771de69a364caf268b648333c69c97b5727f132605ec01c51d2d0/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string218 = /776a5e227d275f6a777ea5c7886e69efe5b9ee9da3fd79700965f4809cde5d27/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string219 = /7b2aeb01bd57aa53f1d615294fa425aaa3d82f43474ed529d9a33efb873a183e/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string220 = /7d9713740d78deeabff15b6080a387460a315a680777d4f1e04c498f1b708826/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string221 = /7d97c9853b4bfb386f351545d1a4c0bafea316ccc6ca9c710a3db65ac622067a/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string222 = /7ec46c20cc8b0d99d230cf54b0e12d97ac4a5049f22badbe7164e7b6d75607d1/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string223 = /7f21c8cb257523a9e810b7e7ae76308b2740fef55dc13f265c427876aa87b559/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string224 = /7f4747710ba404d04c752320fce43e95fc680ee631fdee2e7ae3ceddb84420a9/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string225 = /8558ee2389b4493ff9b3d9bcab252564a817284583d651649ce79d7091ea45d3/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string226 = /89a1b21160a0e3890c45596d7832ff37474a2c3200423f23adee11ff676b295b/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string227 = /8c191b2d03ec58627fd172193f1b90871524c5ebffe364f71308ee74de5168d4/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string228 = /8c35ea32fdfbf8dd949fb86b3f8badfb46d40cfbb6fb80fb174c0a39cc1547df/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string229 = /8e34869d0ba4e0fce056c0c000758541cb48a494ee6e7b516cb3085ded7e44c7/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string230 = /90eff64c5a742c7d96d87648a15bcb33145ebebab593f0c0161dae22880b90a0/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string231 = /91c60eb7b5f95951e96a2437ee51dbae7821377e8e4864279b41c53791481b6a/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string232 = /92a11c9ee2af4ffb55d05210813c7ff309f90274a1d211018acc2643367b2534/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string233 = /94004895c51abc532d7bddc290fa71d5b390dec2daa7d4b9ecc6e257896ac564/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string234 = /9bb03c64894f76241a0c97d210a95a8a5d538a660b8067b1748dd157b1ddeaa6/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string235 = /9bc358f934bfbeb12347083aef6b7a6efe26846b83ce0e653a4b89c64ba89073/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string236 = /a1f3b5d701bc32776e8a37bcda5a73dbde9d5b1de9f6037aac09cbbb2542d1cf/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string237 = /a20fb6cf0d1e9c86de68b8665fbbf0974b04c69beccd41d7123f6b3004221beb/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string238 = /a22417b2eccc3ab5a32aecee8bd004cbbef73fe80d58119d23223163985d1f6b/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string239 = /a2798030e4a1455864158becf472780f95d347588b681031366fb776741c0880/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string240 = /a347a180847fa3dca00bc28dd1321f5b332fdf574c73ea2b30ef3fab63b2380b/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string241 = /a45f1250e0125326747fcd299ef10b98e39b4fa7e6d6865dabe0a6c8225013ef/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string242 = /a48dfc0e20bd69e3774d74860f2a74691addf9fbaae42c71450561a4d526f92a/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string243 = /aa3244dd4ccc78f549783e6f27951d294aa6a54f349bd9eef5c89830e1742505/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string244 = /aab45aa9eac5e0b9865f44a234f6c5cddbc3b2fcb14aa4fee101cbcef2ba37d8/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string245 = /ab36f1dcf6cfd93b95bf5394b1ef22deff505df685c9b0a36d25fa9c94f4b548/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string246 = /abb90f97b0e132f7d40af31e0935f7d15bb737d2ee59650e6846ddbca1f8afe9/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string247 = /ac1d8b0b8458ec134d5c85fa863c3d8ed016e35454dedae79698ad0818919b7f/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string248 = /add7fb1cea253b5e58f7ab41b8db1ef3438c6dd59c6f5d95dfc18c60097ca5f3/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string249 = /api\@mega\.nz/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string250 = /apt\sinstall\s.{0,1000}megacmd/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string251 = /b159333d4411c72736ec1c54cbca34c6ead9ff7779de79dc968387e61570f0d5/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string252 = /b309f0785461dbe35a63b0a674cc70381ef7f87720d2aa884a8dbc8ae3c2c42e/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string253 = /b47b85efda1561b559c7d1a81e0d4b49958607f6e4933bf46f97f43c917f69a7/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string254 = /b4fd5651fedd284d57bae7f1eee41e3f9ef77e2d21014159081ce9200f886ace/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string255 = /b69c2f0acc58d45ae4dae502892af08ce9abaa0de2433573a07e9a06fae3a255/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string256 = /b6ff6c05c78901dfc6291751bab1ae93a0ac836d8d506e57d2bb6fb927facc7d/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string257 = /b7b76dbe6c1976ebdb81e3b87284910f581cc79b7baa9f5073b0193c6f16b0d8/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string258 = /b9c52c18fb7f1b046650f606aa2904b18b73108bc9fde5000a7953a294169532/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string259 = /baf01944477c9b110f7f0edf02e4c129e63e78d4a3e87db667e9b6bb2d8aeaad/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string260 = /bea14bb7e2fa975cdb9d73a326b3d4e7fdd0176774279e83e072641b8a8bfdfd/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string261 = /c0f2a8d4c63349b7e3a5a34bae4a0994152c49bb4ee200ee4705b5599eef1b31/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string262 = /c175bb05f516d617d49d4b0032f71265bf95c7e62c334ee16c0f3c3f87dbbe77/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string263 = /c185b75ecfe16724160530bedfe237537b23e3dc2ec2f38869fa6698bf12ce74/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string264 = /c39719e5e79043b28a6368cdc942032bf5b2ab18fff2f66bd726058e9e921ef7/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string265 = /c6f2a4b09f9249c4e77ad03cc0e15940f080c125187137bc88a7d2adf2a4916f/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string266 = /caed90cc51561edd29eb5e842c266add1bb477261cf5254a0e2c218ed0737b93/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string267 = /cb984e4a89d00bb86a40eab7f7920e2bb739e3eb69a35596586f45e06619961f/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string268 = /cfcdba9a1f3f660957120a8096f37fba92e92e89a24a18c916130ab459cfcf73/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string269 = /d3b331e8568b4aa59710b2a731541d625138fa0d37aa26fda679a6b8713827ad/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string270 = /d42e64cfcb227a43ebd33e91b8bf5f49c8095f588477a9400d1107aab52b84f4/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string271 = /d57684855baf42e911b235c7ffb5a106aac875461d5faeb059c4d941e7b5cfd6/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string272 = /d692deb721e9ac81db35e26542abbc64f26aebb0f232dab53d390de7a03461da/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string273 = /d9b6a53b78a6ac70f165ebebd6ebea9de40da7b200a92d576ac3d687a27e158e/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string274 = /dc0cea82985d2d307bfe4f5bd44736410c481b1d6070bac185b90bf1b53a7e5c/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string275 = /dec4ee8bffdeb1c87164239a4104760f440b6399fefc897edd37f7094ebeb87c/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string276 = /df39fd5831826cb988eb5bfdfb4a98ca75eda8c03f6acdc286a7741448849c9b/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string277 = /df52291409a56fd512402124a94b51dda27c0b5caf2c93d36932e6ce2268bb3c/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string278 = /dnf\sinstall\s.{0,1000}megacmd/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string279 = /e45eeac40ace7b050f9747d79954c4b7bb82792b727a691799694f109938b338/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string280 = /e5d799f4ebb0f0a02c6c7efb0fd946a9a9f7b8283c5ccb697132974711060ccf/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string281 = /e7ed5baca1c5f53c18e8d01bdb0e4d0f78b82bc72cb3afedac54a8ef8209ca34/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string282 = /eb1290f3e5914a7805f2767885b743705ac1526774f32f82ee14d899b0b43374/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string283 = /eb58f70f2f5fb48cab8eb1127276b9a52bed2ba60e56f168ba3dc69d71d5f736/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string284 = /ec616fea07e36749e5846b97eebe23138c7012699155f8a2cbd9c6c3e0b8bfca/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string285 = /f47d36b9cf879546d44f0efd0fe2e4c1fcd75a13f4d7eb3fb8e40296a1f333b2/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string286 = /f4f31a262a9a63438734a81d89462898a082278a49a41bed2f39792a6b3dbcc5/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string287 = /f5793c201602a3619cac14d31d0356d058d8128b13027b1e64073dd029193614/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string288 = /f5cc9ce16100354271c7b385377053076c486cba84f21151a65721d24caecf09/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string289 = /f64064f35b2c464cb20fdcb70a8aa73856b6a8af65acd5be8d58b79df9889c1c/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string290 = /f830d20d4677677a10833cee5fbfa7717d8b2d90a5ddc1fc0153426aa7267ec0/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string291 = /fbb81f40c843fc33e57a23db01ee0f206c99c6ed75520a5594e0b3d525725215/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string292 = /ff9d4086614006d6372ab2ac9d750701157e40285452aba802460da8f91c404f/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string293 = /from\smegacmd_tests_common\simport\s/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string294 = /https\:\/\/mega\.io\/cmd\#download/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string295 = /https\:\/\/mega\.nz\/folder\/8L80QKyL\#glRTp6Zc0gppwp03IG03tA/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string296 = /https\:\/\/mega\.nz\/folder\/bxomFKwL\#3V1dUJFzL98t1GqXX29IXg/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string297 = /https\:\/\/mega\.nz\/folder\/D0w0nYiY\#egvjqP5R\-anbBdsJg8QRVg/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string298 = /https\:\/\/mega\.nz\/folder\/gflVFLhC\#6neMkeJrt4dWboRTc1NLUg/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string299 = /https\:\/\/mega\.nz\/linux\/repo\/.{0,1000}\.deb/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string300 = /killall\smega\-cmd/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string301 = /killall\smega\-cmd\-server/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string302 = /linux\@mega\.co\.nz/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string303 = /MEGA\/MEGAcmdUpdaterTask/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string304 = /MEGAcmd\/.{0,1000}\sMegaClient\// nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string305 = /pacman\s\-U\s.{0,1000}megacmd/ nocase ascii wide
        // Description: Command Line Interactive and Scriptable Application to access MEGA (hosting service abused by attackers)
        // Reference: https://github.com/meganz/MEGAcmd
        $string306 = /subprocess\.Popen\(MEGACMDSHELL/ nocase ascii wide

    condition:
        any of them
}
