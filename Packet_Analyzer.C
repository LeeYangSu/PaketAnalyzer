#include <stdio.h>
#include <pcap/pcap.h>

void Hexa_View(unsigned char *);

char errbuf[PCAP_ERRBUF_SIZE];   // 에러 메세지 저장 버프
                                 // PCAP_ERRBUF_SIZE는 256으로 pcap.h에 정의되어 있다.
int main(void)
{
	char *NIC_name;
	unsigned char *buf[1400] = {0, }; // 0으로 초기화
	pcap_t *NIC_dev;
	struct pcap_pkthdr infor;

	NIC_name = pcap_lookupdev(errbuf);
	if( NULL == NIC_name)              // pcap_lookupdev는 실패시 NULL을 반환한다.
	{
		printf("Not found NIC_name\n");
		return 0;
	}

	NIC_dev = pcap_open_live(NIC_name, 1400, 1, 0, errbuf);
	if( NULL == NIC_dev)              // pcap_open_live는 실패시 NULL을 반환한다.
	{
		printf("Device open error : %s\n", errbuf);
		return 0;
	}

	ucData = pcap_next(NIC_dev, &infor);
	Hexa_View((unsigned char *)ucData);

	printf("MAC[ %02X : %02X : %02X : %02X : %02X : %02X ] <- "
		"MAC[ %02X : %02X : %02X : %02X : %02X : %02X ]\n"
		, *(ucData + 0)
		, *(ucData + 1)
		, *(ucData + 2)
		, *(ucData + 3)
		, *(ucData + 4)
		, *(ucData + 5)
		, *(ucData + 6)
		, *(ucData + 7)
		, *(ucData + 8)
		, *(ucData + 9)
		, *(ucData + 10)
		, *(ucData + 11)
		, *(ucData + 12));
	if(0x45 == *(ucData + 14))
	{
		printf("IP[ %d : %d : %d : %d ] <- [ %d : %d : %d : %d ]\n"
			, *(ucData + 26)
			, *(ucData + 27)
			, *(ucData + 28)
			, *(ucData + 29)
			, *(ucData + 30)
			, *(ucData + 31)
			, *(ucData + 32)
			, *(ucData + 33));
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
