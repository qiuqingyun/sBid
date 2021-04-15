#pragma once
#include "base.h"

using namespace std;

const int BUF_SIZE = 2048;

class Network
{
public:
	void init(string codeName, bool bigMe, int port);		 //��ʼ��
	bool mSend(string send_string);							 //����һ��string
	bool mReceive(string& recv_string);						 //����һ��string
	void deserialization(string str, vector<string>& strs);//�����л�
	~Network();
	int sockSer = -1, sockCli = -1;
	bool bigMe;
	string codeName;
	string delimiter = ";";
private:
	string IP = "127.0.0.1";
	int port;
	struct sockaddr_in addrSer, addrCli;
	char recvSizeBuf[BUF_SIZE];
	char checkBuf[BUF_SIZE];

	bool mSend(int fd, string send_string);
	bool mReceive(int fd, string& recv_string);
};