#pragma once
#include "base.h"

using namespace std;

const int BUF_SIZE = 2048;

class Network
{
public:
	void init(string codeName, bool bigMe, int port);		 //初始化
	bool mSend(string send_string);							 //发送一个string
	bool mReceive(string& recv_string);						 //接收一个string
	void fSend(string fileName);							//发送一个文件
	void fReceive(string fileName);							//接收一个文件
	void deserialization(string str, vector<string>& strs);//反序列化
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