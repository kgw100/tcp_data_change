#include <sfdafx.h>
#include <util.h>
#include <data_cg.h>
extern const char * fr_str;
extern const char * to_str;

int main(int argc, const char* argv[])
{
   //check parameter
    if(argc != 3) {
         usage();
         return -1;
     }
     struct nfq_handle *handle;
     struct nfq_q_handle *q_handle;
     int fd;
     int rv;
     char buf[4096] __attribute__ ((aligned));
//     u_char * buf;
     fr_str = argv[1];
     to_str = argv[2];

     handle = nfq_open();
     if(!handle){
            fprintf(stderr,"Erro d(uring opening nfq!\n");
            exit(-1);
     }
     printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
         if (nfq_bind_pf(handle, AF_INET) < 0) {
             fprintf(stderr, "error during nfq_bind_pf()\n");
             exit(1);
         }

    printf("HI\n");
     q_handle = nfq_create_queue(handle,  0, &cb, buf);
     if (!q_handle) {
         fprintf(stderr, "error during nfq_create_queue()\n");
         exit(1);
     }
     if(nfq_set_mode(q_handle,NFQNL_COPY_PACKET,0xffff)<0){
         fprintf(stderr, "can't set packet_copy mode\n");
         exit(-1);
     }
    fd = nfq_fd(handle); //for receive packet. Get file discriptor associated with nfq handler
    for (;;) {

            if ((rv = static_cast<int>(recv(fd, buf, sizeof(buf), 0))) >= 0) {
                printf("pkt received\n");
                nfq_handle_packet(handle, buf, rv);
                continue;
            }

            if (rv < 0 && errno == ENOBUFS) {
                printf("losing packets!\n");
                continue;
            }
            perror("recv failed");
            break;
        }


    nfq_destroy_queue(q_handle); //unbinding from queue


    nfq_unbind_pf(handle,AF_INET);

    nfq_close(handle);// closing nfq handle

    return 0;
}
