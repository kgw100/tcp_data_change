#include <sfdafx.h>
#include <data_cg.h>
#include <util.h>
#include <key.h>

char * fr_str;
char * to_str;

#pragma pack(push,1)
struct cs_hdr{
    uint32_t sip;
    uint32_t dip;
    uint8_t rsv = 0;
    uint8_t proto;
    uint16_t tcp_len;
};
#pragma pack(pop)
#define CARRY 65536

int cb(struct nfq_q_handle *q_handle, struct nfgenmsg *nfmsg,
          struct nfq_data *nfa, void *data)
{
    static unordered_map<tuple_key, vector<uint32_t>,tuple_hash,key_equal> CgData_HashMap;
    static unordered_map<tuple_key, vector<uint32_t>,tuple_hash,key_equal>::iterator iter;
    int id = 0;
    struct nfqnl_msg_packet_hdr *ph;
    uint32_t payload_len;
    u_char *cg_data;
    string cg_data_str;
    uint16_t cg_data_len ;
    int i = 0;
    ph = nfq_get_msg_packet_hdr(nfa);
    if (ph ) {
        id = ntohl(ph->packet_id);
    }
    payload_len =static_cast<uint32_t>(nfq_get_payload(nfa, &cg_data));

    if(payload_len != 0){
      struct iphdr * iph =reinterpret_cast<struct iphdr*>(cg_data);
      struct tcphdr * tcph = reinterpret_cast<struct tcphdr*>(cg_data + iph->ihl*4);
      if(iph->protocol ==6){
      uint8_t * payload = cg_data + (iph->ihl*4) + (tcph->th_off*4);
      uint32_t fr_str_len = strlen(fr_str);
      uint32_t to_str_len = strlen(to_str);
      int gap_len = to_str_len - fr_str_len;
      uint8_t temp_data[1500];

      Tuple_key key;
      tuple_key tuple_key;
      uint32_t flow;

      if(iph->saddr < iph->daddr)
      {
          Tuple_key(iph->saddr,iph->daddr,tcph->th_sport,tcph->th_dport);
          tuple_key = make_tuple(iph->saddr,iph->daddr,tcph->th_sport,tcph->th_dport);
          CgData_HashMap[tuple_key]=vector<uint32_t>{0,0};
          iter = CgData_HashMap.find(tuple_key);
          flow = 0;
      }
      else
      {
          Tuple_key(iph->daddr,iph->saddr,tcph->th_dport,tcph->th_sport);
          tuple_key = make_tuple(iph->daddr,iph->saddr,tcph->th_dport,tcph->th_sport);
          CgData_HashMap[tuple_key]=vector<uint32_t>{0,0};
          iter = CgData_HashMap.find(tuple_key);
          flow = 1;
      }

      if(iter == CgData_HashMap.end())
      {
          iter->second[0] = 0;
          iter->second[1] = flow;
      }

      if(iter->second[1] == flow)
      {
          if(gap_len < 0)
          {
              tcph->seq -= htonl(-(iter->second[0]));
          }
          else
          {
              tcph->seq += htonl(-(iter->second[0]));
          }
      }
      else
      {
          if(gap_len < 0)
          {
              tcph->ack_seq += htonl(iter->second[0]);
          }
          else
          {
              tcph->ack_seq -= htonl(iter->second[0]);
          }
      }

      int cur_idx = 0;

      while(cur_idx < payload_len - (fr_str_len - 1))
      {
          if(!memcmp(payload + cur_idx, fr_str, fr_str_len))
          {
              memset(temp_data, 0, 1500);
              memcpy(temp_data, payload + cur_idx + fr_str_len, payload_len - (cur_idx + fr_str_len));
              memcpy(payload + cur_idx, to_str, to_str_len);
              memcpy(payload + cur_idx + to_str_len, temp_data, payload_len - (cur_idx + to_str_len));

              iter->second[0] += gap_len;

              if(gap_len < 0)
              {
                  iph->tot_len -= htons(-gap_len);
              }
              else
              {
                  iph->tot_len += htons(gap_len);
              }

              payload_len += gap_len;
              cur_idx+= to_str_len;

              iter->second[1] = flow;
          }
          else cur_idx++;
      }
      get_checksum_ip(temp_data);
      get_checksum_tcp(temp_data);

      key.print_Tuple_key();
      printf("------------------------------------------------------------\n");
      return nfq_set_verdict(q_handle, id, NF_ACCEPT,payload_len, cg_data);
        }
    }
     return nfq_set_verdict(q_handle, id, NF_ACCEPT,0, nullptr);
}
uint16_t calc_checksum(uint16_t * data, uint32_t data_len)
{
    uint32_t temp_checksum = 0;
    uint16_t checksum;

    uint32_t cnt, flow;

    if(data_len % 2 == 0)
    {
        cnt = data_len / 2;
        flow = 0;
    }
    else {
        cnt = (data_len / 2) + 1;
        flow = 1;
    }

    for(int i = 0; i < cnt; i++)
    {
        if((i + 1) == cnt && flow == 1)
            temp_checksum += ntohs((data[i] & 0x00ff));
        else
            temp_checksum += ntohs(data[i]);

    }

    temp_checksum = ((temp_checksum >> 16) & 0xffff) + temp_checksum & 0xffff;
    temp_checksum = ((temp_checksum >> 16) & 0xffff) + temp_checksum & 0xffff;

    checksum = temp_checksum;

    return checksum;
}
uint16_t get_checksum_ip(u_char * data)
{
    struct iphdr * iph = reinterpret_cast<struct iphdr*>(data);
    uint16_t checksum;
    in_addr sip,dip;
    memcpy(&(sip).s_addr,&iph->saddr,sizeof(sip));
    memcpy(&(dip).s_addr,&iph->daddr,sizeof(dip));
    string src_ip =string(inet_ntoa(sip));
    string dst_ip =string(inet_ntoa(dip));
    cout<<"SIP:"<< src_ip;
    cout<<" DIP:"<< dst_ip;
    iph->check = 0;
    checksum = calc_checksum(reinterpret_cast<uint16_t *>(iph), (iph->ihl*4));

    iph ->check = htons(checksum ^ 0xffff); //for tcp checksum

    return iph->check;
}

uint16_t get_checksum_tcp(uint8_t * data)
{
    struct iphdr * iphdr = reinterpret_cast<struct iphdr*>(data);
    struct tcphdr * tcphdr = reinterpret_cast<struct tcphdr*>(data + iphdr->ihl*4);

    struct cs_hdr cs_hdr;

    memcpy(&cs_hdr.sip, &iphdr->saddr, sizeof(uint32_t));
    memcpy(&cs_hdr.dip, &iphdr->daddr, sizeof(uint32_t));
    cs_hdr.rsv = 0;
    cs_hdr.proto = iphdr->protocol;
    cs_hdr.tcp_len = htons(ntohs(iphdr->tot_len) - (iphdr->ihl*4));

    uint16_t temp_checksum_pseudo, temp_checksum_tcp, checksum;
    uint32_t temp_checksum;
    tcphdr->check = 0;

    temp_checksum_pseudo = calc_checksum(reinterpret_cast<uint16_t *>(&cs_hdr), sizeof(cs_hdr));
    temp_checksum_tcp = calc_checksum(reinterpret_cast<uint16_t *>(tcphdr), ntohs(cs_hdr.tcp_len));

    temp_checksum = temp_checksum_pseudo + temp_checksum_tcp;

    temp_checksum = ((temp_checksum >> 16) & 0xffff) + temp_checksum & 0xffff;

    temp_checksum = ((temp_checksum >> 16) & 0xffff) + temp_checksum & 0xffff;

    checksum = temp_checksum;

    tcphdr->check = htons(checksum ^ 0xffff);

    return tcphdr->check;
}
//static u_int32_t data_change(struct nfq_data *tb, u_char *data)
//{
//    int id = 0;
//    struct nfqnl_msg_packet_hdr *ph;
//    uint32_t payload_len;
////    u_char * data;
//    u_char *cg_data;
//    string cg_data_str;
//    uint16_t cg_data_len ;

//    int i = 0;
//    ph = nfq_get_msg_packet_hdr(tb);
//    if (ph && ph->hw_protocol ==htons(0x0800)) {
//        id = ntohl(ph->packet_id);
//    }
//    payload_len =static_cast<uint32_t>(nfq_get_payload(tb, &data));

//    if(payload_len != 0){
//    struct iphdr * iph =reinterpret_cast<struct iphdr*>(data);
//    struct tcphdr * tcph = reinterpret_cast<struct tcphdr*>(data + iph->ihl*4);
////    uint8_t * payload = data +(iph->ihl*4)+(tcph->th_off+4);
//    string data_str;
//    data_str.assign(reinterpret_cast<char *>(data),payload_len);
//    string test_str = "aaa";
////    cg_data_str = replaceString(data_str,fr_str, to_str);
//    printf("FROM_STR %s",fr_str);
//    printf("TO_STR: %s",to_str);
//    int pos = 0;
//    if (!isvalid(fr_str) || !isvalid((to_str))) {
//    }
//    else {
//        while((pos = data_str.find(fr_str, pos))> 0)//(pos = data_str.find(fr_str, pos)) != string::npos
//        {
//            data_str.replace(pos, strlen(fr_str), to_str);
//            pos +=strlen(to_str);
//        }
//    }
//    data = reinterpret_cast<u_char *>(const_cast<char*>(data_str.c_str()));
//    cg_data_len = string(data_str).size();

////    strcpy((char*)data, data_str.c_str()); //change data
////    get_checksum_ip(data);
////    get_checksum_tcp(data);
//    memset(global_packet, 0, 4096);
//    memcpy(global_packet, data, payload_len);
//    global_ret = payload_len;
//    get_checksum_ip(global_packet);
//    get_checksum_tcp(global_packet);

//    printf("Before_data_len:%d",data_str.size());
//    printf("CG_DATA_LEN :%d",cg_data_len);
////    printf("RES_STR: %d",res_str.size());
////      printf("SIZEOF:%d",sizeof (*to_str));
////    printf("FR_STR: %s ",fr_str);
////    printf("TO_STR: %s ",to_str);
////    printf("IP_CHECKSUM: %04X ",);
////    printf("TCP_CHECKSUM: %04X ",);
////    printf("RES_STR :%s",res_str);
////    cout << "RES_STR :"<<res_str <<endl;
////    printf("V_DATA : %d ",data_len);
//    }

//    return static_cast<u_int32_t>(id);
//}

