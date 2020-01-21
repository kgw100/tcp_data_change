#pragma once
#include <sfdafx.h>

void dump(u_char *buf, size_t len);
uint16_t ip_sum_calc(iphdr *ip_hdr_pac, u_char * buf);
uint16_t get_checksum_ip(u_char * data);
uint16_t calc_checksum(uint16_t * data, uint32_t data_len);
uint16_t get_checksum_tcp(uint8_t * data);

