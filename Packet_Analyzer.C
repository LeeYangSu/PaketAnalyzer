#include <stdio.h>
#include <pcap/pcap.h>
#include <net/ethernet.h>

void Hexa_View(unsigned char *);

char errbuf[PCAP_ERRBUF_SIZE];   // 에러 메세지 저장 버프
                                 // PCAP_ERRBUF_SIZE는 256으로 pcap.h에 정의되어 있다.
int main(void)
{
	char *NIC_name;
	unsigned char *buf[1400] = {0, };   // 0으로 초기화
	pcap_t *NIC_dev;
	struct pcap_pkthdr infor;
	struct ether_header *st_Ether;

	NIC_name = pcap_lookupdev(errbuf);
	if( NULL == NIC_name)                // pcap_lookupdev는 실패시 NULL을 반환한다.
	{
		printf("Not found NIC_name\n");
		return 0;
	}

	NIC_dev = pcap_open_live(NIC_name,   // 읽어올 장치의 장치명. pcap_lookupdev함수를 통해 얻은 값을 넣어준다. 
							 1400,       // 읽어들일 패킷의 최대 크기.
							 1,          // 패킷을 읽어들일 방식을 성정하는 값( 1 = 조건없이 모든 패킷을 읽어들임.)
							 0,          // 패킷이 노기까지의 대기시간을 나타냄( 0 = 패킷이 놀때까지 무기한 기다림.)
							 errbuf);    // 에러를 처리할 버퍼의 주소.

	if( NULL == NIC_dev)                 // pcap_open_live는 실패시 NULL을 반환한다.
	{
		printf("Device open error : %s\n", errbuf);
		return 0;
	}

	ucData = pcap_next(NIC_dev, &infor);
	Hexa_View((unsigned char *)ucData);  // Hexa View로 건져올린 패킷을 확인.

	printf("LAN Card Type : ");          // LAN Card Type 확인.
	switch(pcap_datalink(NIC_dev))
	{
		case DLT_NULL : 
			printf(" no link-layer encapsulation\n");
			break;
		case DLT_EN10MB : 
			printf("Ethernet (10Mb)\n");
			break;
		case DLT_EN3MB : 
			printf("Experimental Ethernet (3Mb)\n");
			break;
		case DLT_AX25 : 
			printf("Amateur Radio AX.25\n");
			break;
		case DLT_PRONET : 
			printf("Proteon ProNET Token Ring\n");
			break;
		case DLT_CHAOS : 
			printf("Chaos\n");
			break;
		case DLT_IEEE802 : 
			printf("IEEE 802 Networks\n");
			break;
		case DLT_ARCNET : 
			printf(" ARCNET \n");
			break;
		case DLT_SLIP : 
			printf("Serial Line IP\n");
			break;
		case DLT_PPP: 
			printf("Point-to-point Protocol\n");
			break;
		case DLT_FDDI :
			printf("FDDI\n");
			break;	
		default :
			printf("Unknown type\n");
			break;
	}

	st_Ether =(struct ether_header *)UC_data;  // MAC Address 6자리 [도착] <- [출발] 확인.
	printf("MAC [%02X:%02X:%02X:%02X:%02X:%02X] <-"
			"[%02X:%02X:%02X:%02X:%02X:%02X]\n",
			st_Ether -> ether_dhost[0],
			st_Ether -> ether_dhost[1],
			st_Ether -> ether_dhost[2],
			st_Ether -> ether_dhost[3],
			st_Ether -> ether_dhost[4],
			st_Ether -> ether_dhost[5],
			st_Ether -> ether_shost[0],
			st_Ether -> ether_shost[1],
			st_Ether -> ether_shost[2],
			st_Ether -> ether_shost[3],
			st_Ether -> ether_shost[4],
			st_Ether -> ether_shost[5]);

	switch(ntohs(st_Ether -> ether_type))     // Ethernet Type 확인.
	{
		case ETHERTYPE_PUP :
			printf("Xerox PUP\n");
			break;
		case ETHERTYPE_IP :
			printf("IP\n");
			break;
		case ETHERTYPE_ARP :
			printf("Address resolution");
			break;
		case ETHERTYPE_REVARP :
			printf("Reverse ARP\n");
			break;	
		default:
			printf("Unknown Type\n");
			break;
	}

	pcap_close(NIC_dev);
	return 0;
}

void Hexa_View(unsigned char *ucp)
{
	unsigned int icnt;
	unsigned int iCnt;
	printf("=========================================================================\n");
	printf(" address ");
	for(icnt =0; icnt < 16; icnt++)
	{
		printf("%02X ", icnt);
	}
	printf("      ASCII\n");

	for(iCnt = 0; iCnt < 10; ++iCnt)
	{
		printf("%08X ", ucp);
		for(icnt = 0; icnt < 16; icnt++)
		{
			printf("%02X ", *(ucp + icnt));
		}
		for(icnt = 0; icnt < 16; icnt++)
		{
			if(' ' <= *((signed char *)ucp + icnt))
			{
				printf("%c", *(ucp + icnt));
			}
			else
			{
				putchar('.');
			}
		}
		ucp = ucp + 16;
		printf("\n");
	}
	printf("=========================================================================\n");

	return ;
}
