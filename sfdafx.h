#pragma once
#include <arpa/inet.h>
#include <iostream>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string>
#include <utility>
#include <ostream>
#include <pcap.h>
#include <unordered_map>
#include <vector>
#include <string>
#include <linux/netfilter.h>
#include <linux/types.h>
#include <netinet/in.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <cstring>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <tuple>


using namespace std;

using tuple_key = tuple<uint32_t,uint32_t,uint16_t,uint16_t>;

struct tuple_hash {//:public std::unary_function<tuple_key,std::size_t>
    //pair_hash is possible,
    //but there is some potential for collision
    template<class T1,class T2, class T3, class T4>
    std::size_t operator () (const tuple<T1,T2,T3,T4> &p) const{
        uint poly = 0xEDB8320;
        auto h1 = hash<T1>{}(get<0>(p));
        auto h2 = hash<T2>{}(get<1>(p));
        auto h3 = hash<T3>{}(get<2>(p));
        auto h4 = hash<T4>{}(get<3>(p));

        for(int i =0; i<4; i++){
            poly = (poly <<1)| (poly >>(32-1));
            h1 = poly * h1 + get<0>(p);
            h2 = poly * h2 + get<1>(p);
            h3 = poly * h3 + get<2>(p);
            h4 = poly * h4 + get<3>(p);
        }
        return h1 ^ h2 ^ h3 ^ h4;
    }

};
struct key_equal{//:public std::binary_function<tuple_key,tuple_key,bool>

    bool operator ()(const tuple_key & lhs, const tuple_key &rhs)const{
        return(
                get<0>(lhs) == get<0>(rhs) &&
                get<1>(lhs) == get<1>(rhs) &&
                get<2>(lhs) == get<2>(rhs) &&
                get<3>(lhs) == get<3>(rhs)
              );
        }
};
