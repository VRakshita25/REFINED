rule Mozi_P2P_Botnet {
    meta:
        description  = "Detects Mozi P2P DHT botnet ELF"
        family       = "Mozi"
        type         = "P2P Botnet"
        threat_actor = "Chinese threat actor (arrested 2021, botnet persists)"
        mitre_attack = "T1498, T1071.001, T1083, T1105"
        severity     = "HIGH"
        reference    = "https://blog.netlab.360.com/mozi-another-botnet-using-dht/"

    strings:
        $s1 = "Mozi" ascii
        $s2 = "mozi" nocase ascii
        $s3 = "WAIT_NET_STATE" ascii
        $s4 = "[NKRUN]" ascii
        $s5 = "[NDIP]" ascii
        $s6 = "[NUPDATE]" ascii
        $s7 = "[NHTTPFLOOD]" ascii
        $s8 = "[NUDPFLOOD]" ascii
        $d1 = "BitTorrent protocol" ascii
        $d2 = "get_peers" ascii
        $d3 = "announce_peer" ascii
        $d4 = "find_node" ascii
        $e1 = "wget" ascii
        $e2 = "tftp" ascii
        $e3 = "chmod 777" ascii
        $e4 = "/tmp/mozi" ascii
        $e5 = "bin.sh" ascii
        $p1 = "crontab" ascii
        $p2 = "iptables -A" ascii

    condition:
        uint32(0) == 0x464C457F
        and filesize < 5MB
        and (
            2 of ($s*)
            or 3 of ($d*)
            or (1 of ($s*) and 2 of ($d*))
            or (1 of ($s*) and 2 of ($e*))
            or (3 of ($e*))
        )
}

rule Mozi_Config_Tags {
    meta:
        description = "Detects Mozi embedded config tags"
        family      = "Mozi"
        type        = "P2P Botnet"
        severity    = "HIGH"

    strings:
        $t1 = "[NKRUN]" ascii
        $t2 = "[NDIP]" ascii
        $t3 = "[NUPDATE]" ascii
        $t4 = "[NHTTPFLOOD]" ascii
        $t5 = "[NUDPFLOOD]" ascii

    condition:
        uint32(0) == 0x464C457F
        and 3 of them
}

rule Mozi_Dropper {
    meta:
        description = "Detects Mozi dropper pattern"
        family      = "Mozi"
        type        = "P2P Botnet"
        severity    = "MEDIUM"

    strings:
        $s1 = "mozi" nocase ascii
        $s2 = "bin.sh" ascii
        $s3 = "wget http" ascii
        $s4 = "chmod" ascii
        $s5 = "/tmp/" ascii

    condition:
        3 of them
}
