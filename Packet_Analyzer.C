#include <stdio.h>
#include <pcap/pcap.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

char errbuf[PCAP_ERRBUF_SIZE];   // 에러 메세지 저장 버프
                                 // PCAP_ERRBUF_SIZE는 256으로 pcap.h에 정의되어 있다.
struct ether_header *st_Ether;
struct ip *stip;

void Hexa_View(unsigned char * );
pcap_t *EMB_open(void);
int EMB_datalink(int ,unsigned char * );
int EMB_ipHeader(int );
void EMB_udpHeader(void);
void EMB_tcpHeader(void);

int main()
{
	int choose_pro;
	pcap_t *NIC_dev;
	const unsigned char *ucData;
	struct pcap_pkthdr infor;

	NIC_dev = EMB_open();
	if(0 == NIC_dev)
	{
		return 0;
	}
	
	ucData = pcap_next(NIC_dev, &infor);
	Hexa_View((unsigned char *)ucData);                 // Hexa View로 건져올린 패킷을 확인.
	EMB_datalink(pcap_datalink(NIC_dev), ucData);       // ETHNET Header
	choose_pro = EMB_ipHeader(pcap_datalink(NIC_dev));  // IP Header

	switch(choose_pro)
	{
		case IPPROTO_UDP:
			EMB_udpHeader();
			break;
		case IPPROTO_TCP:
			EMB_tcpHeader();
			break;
		default:
			break;
	}

	pcap_close(NIC_dev);
	return 0;
}

void EMB_udpHeader(void)
{
	struct udphdr *udp_infor;
	
	udp_infor = (struct udphdr *)(stip + 1);
	printf("[ UDP Header ]===========================================================\n");
	printf("Source Port      : %d\n", udp_infor->source);
	printf("Destination Port : %d\n", udp_infor->dest);
	printf("Datagram Length  : %d\n", udp_infor->len);
	printf("Checksum         : %04X\n", ntohs(udp_infor->check));
	printf("=========================================================================\n");
	printf("\n");
	
	return ;
}

void EMB_tcpHeader(void)
{
	struct tcphdr *tcp_infor;

	tcp_infor = (struct tcphdr *)(stip + 1);
	printf("[ TCP Header ]===========================================================\n");
	printf("Source Port             (SPT) : %d\n", ntohs(tcp_infor->source));
	printf("Destination Port        (DPT) : %d\n", ntohs(tcp_infor->dest));
	printf("Sequence Number         (SEQ) : %04X\n", ntohs(tcp_infor->seq));
	printf("Acknownledgement Number (ACK) : %04X\n", ntohs(tcp_infor->ack_seq));
	printf("Flags\n");
	printf("\t- urg : %s\n", (1 == (tcp_infor->urg))?"set":"not set");
	printf("\t- ack : %s\n", (1 == (tcp_infor->ack))?"set":"not set");
	printf("\t- psh : %s\n", (1 == (tcp_infor->psh))?"set":"not set");
	printf("\t- rst : %s\n", (1 == (tcp_infor->rst))?"set":"not set");
	printf("\t- syn : %s\n", (1 == (tcp_infor->syn))?"set":"not set");
	printf("\t- fin : %s\n", (1 == (tcp_infor->fin))?"set":"not set");
	printf("Window Size                   : %d\n", tcp_infor->window);
	printf("Checksum                      : %d\n", tcp_infor->check);
	printf("=========================================================================\n");
	printf("\n");

	return ;
}

pcap_t *EMB_open(void)
{
	char *NIC_name;
	pcap_t *NIC_dev;
	
	NIC_name = pcap_lookupdev(errbuf);
	if(NIC_name == NULL)                 // pcap_lookupdev는 실패시 NULL을 반환한다.
	{
		printf("Not found NIC_name\n");
		return 0;
	}
	
	NIC_dev = pcap_open_live(NIC_name,   // 읽어올 장치의 장치명. pcap_lookupdev함수를 통해 얻은 값을 넣어준다. 
							 1400,       // 읽어들일 패킷의 최대 크기.
							 1,          // 패킷을 읽어들일 방식을 성정하는 값( 1 = 조건없이 모든 패킷을 읽어들임.)
							 0,          // 패킷이 노기까지의 대기시간을 나타냄( 0 = 패킷이 놀때까지 무기한 기다림.)
							 errbuf);    // 에러를 처리할 버퍼의 주소.
	if(NIC_dev == NULL)
	{
		printf("Device open error : %s\n", errbuf);
		return 0;
	}
	
	return NIC_dev;
}

int EMB_datalink(int type, unsigned char *data)
{
	
	printf("[ Ethernet Header ]======================================================\n");
	printf("LAN Card Type : ");          // LAN Card Type 확인.
	switch(type)
	{
		case DLT_NULL:
			printf("no link-layer encapsulation\n");
			*data = 0;
			break;
		case DLT_EN10MB:
			printf("Ethernet (10Mb)\n");
			st_Ether = (struct ether_header *)(data);
			break;
		case DLT_EN3MB:
			printf("Experimental Ethernet (3Mb)\n");
			break;
		case DLT_AX25:
			printf("Amateur Radio AX.25\n");
			break;
		case DLT_PRONET:
			printf("Proteon ProNET Token Ring\n");
			break;
		case DLT_CHAOS:
			printf("Chaos\n");
			break;
		case DLT_IEEE802:
			printf("IEEE 802 Networks\n");
			break;
		case DLT_ARCNET:
			printf("ARCNET\n");
			break;
		case DLT_SLIP:
			printf("Serial Line IP\n");
			break;
		case DLT_PPP:
			printf("Point-to-point Protocol\n");
			break;
		case DLT_FDDI:
			printf("FDDI\n");
			break;
		default :
			printf("Unknown LAN CARD\n");
			break;
	}
	
	printf("MAC [%02X : %02X : %02X : %02X : %02X : %02X] <- "   // MAC Address 6자리 [도착] <- [출발] 확인.
			"MAC[%02X : %02X : %02X : %02X : %02X : %02X]\n"
			, (st_Ether->ether_dhost[0])
			, (st_Ether->ether_dhost[1])
			, (st_Ether->ether_dhost[2])
			, (st_Ether->ether_dhost[3])
			, (st_Ether->ether_dhost[4])
			, (st_Ether->ether_dhost[5])
			, (st_Ether->ether_shost[0])
			, (st_Ether->ether_shost[1])
			, (st_Ether->ether_shost[2])
			, (st_Ether->ether_shost[3])
			, (st_Ether->ether_shost[4])
			, (st_Ether->ether_shost[5]));

	printf("Type      :");                                        // Ethernet Type 확인.
	switch(ntohs(st_Ether->ether_type))
	{
		case ETHERTYPE_PUP:
			printf("Xerox PUP\n");
			break;
		case ETHERTYPE_IP:
			printf("IP\n");
			break;
		case ETHERTYPE_ARP:
			printf("Address resolution\n");
			break;
		case ETHERTYPE_REVARP:
			printf("Reverse ARP\n");
			break;
		default:
			printf("Unknown Type\n");
			break;
	}
	printf("=========================================================================\n");
	printf("\n");
	
	return 0;
}

int EMB_ipHeader(int type)
{

	printf("[ IP Header ]============================================================\n");
	printf("%04X\n", ntohs(type));
	stip=(struct ip *)(st_Ether+1);
	printf("Version               : %d\n", stip->ip_v);
	printf("Header Length         : %d\n", 4 * stip->ip_hl);
	printf("Type of Service       : 0X%02X\n", stip->ip_tos);
	printf("Total Length          : %d\n", stip->ip_len);
	printf("Identification        : 0X%04X\n", ntohs(stip->ip_id));
	printf("Reserved Bit          : %s\n", (IP_RF == (ntohs((stip->ip_off) & IP_RF)))?"set":"not set");
	printf("Don't Fragment        : %s\n", (IP_DF == (ntohs((stip->ip_off) & IP_DF)))?"set":"not set");
	printf("More Fragments        : %s\n", (IP_MF == (ntohs((stip->ip_off) & IP_MF)))?"set":"not set");
	printf("Fragment Offset Field : %d\n", ntohs((stip->ip_off) & IP_OFFMASK));
	printf("Time to Live          : %d\n", stip->ip_ttl);
	printf("Protocol              : ");
	switch(stip->ip_p)
	{
	case IPPROTO_IP:
		printf("Dummy protocol for TCP.\n" );
		break;
	/*case IPPROTO_HOPOPTS:
		printf("IPv6 Hop-by-Hop options.\n");
		break;*/
	case IPPROTO_ICMP:
		printf("Internet Control Message Protocol.\n");
		break;
	case IPPROTO_IGMP:
		printf("Internet Group Management Protocol.\n");
		break;
	case IPPROTO_IPIP:
		printf("IPIP tunnels (older KA9Q tunnels use 94).\n");
		break;
	case IPPROTO_TCP:
		printf("Transmission Control Protocol.\n");
		break;
	case IPPROTO_EGP:
		printf("Exterior Gateway Protocol.\n");
		break;
	case IPPROTO_PUP:
		printf("PUP protocol.\n");
		break;
	case IPPROTO_UDP:
		printf("User Datagram Protocol.\n");
		break;
	case IPPROTO_IDP:
		printf("XNS IDP protocol.\n");
		break;
	case IPPROTO_TP:
		printf("SO Transport Protocol Class 4.\n");
		break;
	case IPPROTO_IPV6:
		printf("IPv6 header.\n");
		break;
	case IPPROTO_ROUTING:
		printf("IPv6 routing header.\n");
		break;
	case IPPROTO_FRAGMENT:
		printf("IPv6 fragmentation header.\n");
		break;
	case IPPROTO_RSVP:
		printf("Reservation Protocol.\n");
		break;
	case IPPROTO_GRE:
		printf("General Routing Encapsulation.\n");
		break;
	case IPPROTO_ESP:
		printf("encapsulating security payload.\n");
		break;
	case IPPROTO_AH:
		printf("authentication header.\n");
		break;
	case IPPROTO_ICMPV6:
		printf("ICMPv6.\n");
		break;
	case IPPROTO_NONE:
		printf("IPv6 no next header.\n");
		break;
	case IPPROTO_DSTOPTS:
		printf("IPv6 destination options.\n");
		break;
	case IPPROTO_MTP:
		printf("Multicast Transport Protocol.\n");
		break;
	case IPPROTO_ENCAP:
		printf("Encapsulation Header.\n");
		break;
	case IPPROTO_PIM:
		printf("Protocol Independent Multicast.\n");
		break;
	case IPPROTO_COMP:
		printf("Compression Header Protocol.\n");
		break;
	case IPPROTO_RAW:
		printf("Raw IP packets.\n");
		break;
	default:
		break;
	}
	printf("Checksum              : 0X%04X\n", ntohs(stip->ip_sum));
	printf("IP                    : [%s] ->", inet_ntoa(stip->ip_src));
	printf(" [%s]\n", inet_ntoa(stip->ip_dst));
	printf("=========================================================================\n");
	printf("\n");

	return stip->ip_p;
}

void Hexa_View(unsigned char *buf)
{
	int xcnt;
	int ycnt;

	printf("=========================================================================\n");
	printf(" address ");
	for(xcnt = 0; xcnt < 16; ++xcnt)
	{
		printf("%02X ", xcnt);
	}
	printf("     ASCII\n");
	
	for(xcnt = 0; xcnt < 10; ++xcnt)
	{
		printf("%08X ", buf);
		for(ycnt = 0; ycnt < 16; ++ycnt)
		{
			printf("%02X ", *(buf + ycnt));
		}
		for(ycnt = 0; ycnt < 16; ++ycnt)
		{
			if(' ' <= *((unsigned char *)buf + ycnt))
			{
				printf("%c", *(buf + ycnt));
			}
			else
			{
				putchar('.');
			}
		}
		buf = buf + 16;
		printf("\n");
	}
	printf("=========================================================================\n");
	printf("\n");
		
	return ;
}

