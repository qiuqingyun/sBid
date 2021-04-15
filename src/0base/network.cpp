#include "network.h"

//�����ʼ��
void Network::init(string codeName, bool bigMe, int port)
{
	//cout << "Network preparing " << flush;
	this->codeName = codeName;
	this->bigMe = bigMe;
	this->port = port;
	//����socket
	if ((this->sockSer = socket(AF_INET, SOCK_STREAM, 0)) == -1)
	{
		printf("[%s] - Socket error : %s\n", codeName.c_str(), strerror(errno));
		exit(1);
	}
	//����׽��ֵ�ַ�ṹ��������ַ�壬ip�Ͷ˿ں�
	bzero(&this->addrSer, sizeof(struct sockaddr_in));
	inet_aton((const char*)IP.c_str(), &(this->addrSer.sin_addr));
	this->addrSer.sin_family = AF_INET;
	this->addrSer.sin_port = htons(port);
	int opt = SO_REUSEADDR;
	setsockopt(this->sockSer, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
	// ���ջ�����
	int nRecvBuf = 8 * 1024; //����Ϊ8K
	setsockopt(this->sockSer, SOL_SOCKET, SO_RCVBUF, (const char*)&nRecvBuf, sizeof(int));
	// ���ͻ�����
	int nSendBuf = 8 * 1024; //����Ϊ8K
	setsockopt(this->sockSer, SOL_SOCKET, SO_SNDBUF, (const char*)&nSendBuf, sizeof(int));
	if (bigMe)
	{
		//��
		if (bind(sockSer, (struct sockaddr*)(&this->addrSer), sizeof(struct sockaddr)) == -1)
		{
			printf("[%s] - Bind error : %s\n", codeName.c_str(), strerror(errno));
			exit(1);
		}
		// ����
		if (listen(sockSer, 1) == -1)
		{
			printf("[%s] - Listen error : %s\n", codeName.c_str(), strerror(errno));
			exit(1);
		}
		//����
		socklen_t naddr = sizeof(struct sockaddr_in);
		if ((this->sockCli = accept(this->sockSer, (struct sockaddr*)(&this->addrCli), &naddr)) == -1)
		{
			printf("[%s] - Accept error%s\n", codeName.c_str(), strerror(errno));
			exit(1);
		}
	}
	else
	{
		//����
		int times = 1;
		while (connect(sockSer, (struct sockaddr*)&this->addrSer, sizeof(struct sockaddr)) == -1)
		{
			sleep(times++);
			if (times > 11)
			{
				printf("[%s] - Connect error : %s\n", codeName.c_str(), strerror(errno));
				exit(1);
			}
		}
	}
	//cout << "\rNetwork OK        " << endl;
}

//����һ��string
bool Network::mSend(int fd, string send_string)
{
	char* cstr = new char[send_string.size() + 1];
	strcpy(cstr, send_string.c_str());
	size_t send_size = send_string.size() + 1; //��Ҫ���͵����ݴ�С
	string send_size_string = to_string(send_size);
	char* c_send_size_str = new char[send_size_string.size() + 1];
	strcpy(c_send_size_str, send_size_string.c_str());
	if (send(fd, c_send_size_str, send_size_string.size() + 1, 0) == -1)
	{ //��֪�Է���Ҫ׼���Ļ�������С
		printf("[%s] - Prewrite error : %s\n", codeName.c_str(), strerror(errno));
		exit(1);
	}
	if (recv(fd, this->checkBuf, BUF_SIZE, 0) == -1 && !(strcmp(this->checkBuf, c_send_size_str)))
	{ //����ȷ����Ϣ
		printf("[%s] - Check error : %s\n", codeName.c_str(), strerror(errno));
		exit(1);
	}
	clock_t startS = clock();
	if ((send(fd, cstr, send_size, 0)) == -1)
	{ //��������
		printf("[%s] - Write error : %s\n", codeName.c_str(), strerror(errno));
		exit(1);
	}
	delete[] cstr;
	delete[] c_send_size_str;
	return true;
}

//����һ��string
bool Network::mReceive(int fd, string& recv_string)
{
	recv_string.clear();
	if (recv(fd, this->recvSizeBuf, BUF_SIZE, 0) == -1)
	{ //���ջ������ߴ�
		printf("[%s] - Preread error : %s\n", codeName.c_str(), strerror(errno));
		exit(1);
	}
	if (send(fd, this->recvSizeBuf, BUF_SIZE, 0) == -1)
	{ //����ȷ����Ϣ
		printf("[%s] - Check error : %s\n", codeName.c_str(), strerror(errno));
		exit(1);
	}
	size_t recv_size = stol(this->recvSizeBuf); //���ջ������ߴ�
	char* cstr = new char[recv_size];           //���ջ�����
	memset(cstr, '\0', recv_size);
	ssize_t recv_num, remain_num = recv_size;
	clock_t startR = clock();
	while (remain_num > 1)
	{
		if ((recv_num = recv(fd, cstr, recv_size, 0)) == -1 || recv_num == 0)
		{ //��������
			printf("[%s] - Read error : %s\n", codeName.c_str(), strerror(errno));
			exit(1);
		}
		remain_num -= strlen(cstr);
		recv_string += cstr;
		memset(cstr, '\0', recv_size);
	}
	delete[] cstr;
	return true;
}

//����һ��string
bool Network::mSend(string send_string)
{
	int fd = (bigMe) ? this->sockCli : sockSer;
	this->mSend(fd, send_string);
	return true;
}

//����һ��string
bool Network::mReceive(string& recv_string)
{
	int fd = (bigMe) ? this->sockCli : sockSer;
	this->mReceive(fd, recv_string);
	return true;
}

//�����л�
void Network::deserialization(string str, vector<string>& strs) {
	size_t pos_start = 0, pos_end=0;
	for (int i = 0; i < 32; i++) {
		pos_end = str.find(delimiter, pos_end);
		strs.push_back(str.substr(pos_start, pos_end - pos_start));
		pos_start = ++pos_end;
	}
}
//�ر��׽���
Network::~Network()
{
	if (sockSer)
		close(sockSer);
	if (sockCli)
		close(sockCli);
}