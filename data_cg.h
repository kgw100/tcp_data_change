#pragma once
#include <sfdafx.h>

//struct ip_hdr{
//    uint8_t ip_version:4;
//    uint8_t ip_len:4;
//    uint8_t ip_tos;
//    uint16_t ip_total_length;
//    uint16_t ip_id;
//    uint16_t ip_frag_offset;
//    uint8_t ip_ttl;
//    uint8_t ip_proto;
//    uint16_t ip_checksum;
//    uint32_t sip;
//    uint32_t dip;
//};

void dump(u_char *buf, size_t len);
uint16_t ip_sum_calc(iphdr *ip_hdr_pac, u_char * buf);
uint16_t get_checksum_ip(u_char * data);
uint16_t calc_checksum(uint16_t * data, uint32_t data_len);
uint16_t get_checksum_tcp(uint8_t * data);

