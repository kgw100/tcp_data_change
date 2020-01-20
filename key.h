#pragma once
#include <sfdafx.h>

class Tuple_key
{

public:
    uint32_t saddr;
    uint32_t daddr;
    uint32_t ports;

    Tuple_key() {
    }
    Tuple_key(uint32_t cp_saddr, uint32_t cp_daddr, uint16_t cp_sport, uint16_t cp_dport) : saddr(cp_saddr), daddr(cp_daddr)
    {
        ports = cp_sport;
        ports = (ports << 16) + cp_dport;
    }

    bool operator < (const Tuple_key & tk) const
    {
        if(saddr == tk.saddr)
        {
            if(daddr == tk.daddr)
            {
                return ports < tk.ports;
            }
            else
            {
                return daddr < tk.daddr;
            }
        }
        else
        {
            return saddr < tk.saddr;
        }
    }


    void print_Tuple_key(void)
    {
        printf("%s\t",inet_ntoa(*reinterpret_cast<struct in_addr*>(&saddr)));
        printf("%s\t",inet_ntoa(*reinterpret_cast<struct in_addr*>(&daddr)));
        printf("%u\t%u\n", htons((ports >> 16) & 0xffff), htons(ports & 0xffff));

    }

};
