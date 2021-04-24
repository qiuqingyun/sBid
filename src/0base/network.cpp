#include "network.h"

//网络初始化
void Network::init(string codeName, bool bigMe, int port)
{
	//cout << "Network preparing " << flush;
	this->codeName = codeName;
	this->bigMe = bigMe;
	this->port = port;
	//创建socket
	if ((this->sockSer = socket(AF_INET, SOCK_STREAM, 0)) == -1)
	{
		printf("[%s] - Socket error : %s\n", codeName.c_str(), strerror(errno));
		exit(1);
	}
	//填充套接字地址结构，包括地址族，ip和端口号
	bzero(&this->addrSer, sizeof(struct sockaddr_in));
	inet_aton((const char*)IP.c_str(), &(this->addrSer.sin_addr));
	this->addrSer.sin_family = AF_INET;
	this->addrSer.sin_port = htons(port);
	int opt = SO_REUSEADDR;
	setsockopt(this->sockSer, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
	// 接收缓冲区
	int nRecvBuf = 8 * 1024; //设置为8K
	setsockopt(this->sockSer, SOL_SOCKET, SO_RCVBUF, (const char*)&nRecvBuf, sizeof(int));
	// 发送缓冲区
	int nSendBuf = 8 * 1024; //设置为8K
	setsockopt(this->sockSer, SOL_SOCKET, SO_SNDBUF, (const char*)&nSendBuf, sizeof(int));
	if (bigMe)
	{
		//绑定
		if (bind(sockSer, (struct sockaddr*)(&this->addrSer), sizeof(struct sockaddr)) == -1)
		{
			printf("[%s] - Bind error : %s\n", codeName.c_str(), strerror(errno));
			exit(1);
		}
		// 监听
		if (listen(sockSer, 1) == -1)
		{
			printf("[%s] - Listen error : %s\n", codeName.c_str(), strerror(errno));
			exit(1);
		}
		//接受
		socklen_t naddr = sizeof(struct sockaddr_in);
		if ((this->sockCli = accept(this->sockSer, (struct sockaddr*)(&this->addrCli), &naddr)) == -1)
		{
			printf("[%s] - Accept error%s\n", codeName.c_str(), strerror(errno));
			exit(1);
		}
	}
	else
	{
		//连接
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

//发送一个string
bool Network::mSend(int fd, string send_string)
{
	char* cstr = new char[send_string.size() + 1];
	strcpy(cstr, send_string.c_str());
	size_t send_size = send_string.size() + 1; //需要发送的数据大小
	string send_size_string = to_string(send_size);
	char* c_send_size_str = new char[send_size_string.size() + 1];
	strcpy(c_send_size_str, send_size_string.c_str());
	if (send(fd, c_send_size_str, send_size_string.size() + 1, 0) == -1)
	{ //告知对方需要准备的缓冲区大小
		printf("[%s] - Prewrite error : %s\n", codeName.c_str(), strerror(errno));
		exit(1);
	}
	if (recv(fd, this->checkBuf, BUF_SIZE, 0) == -1 && !(strcmp(this->checkBuf, c_send_size_str)))
	{ //接收确认信息
		printf("[%s] - Check error : %s\n", codeName.c_str(), strerror(errno));
		exit(1);
	}
	clock_t startS = clock();
	if ((send(fd, cstr, send_size, 0)) == -1)
	{ //发送数据
		printf("[%s] - Write error : %s\n", codeName.c_str(), strerror(errno));
		exit(1);
	}
	delete[] cstr;
	delete[] c_send_size_str;
	return true;
}

//接收一个string
bool Network::mReceive(int fd, string& recv_string)
{
	recv_string.clear();
	if (recv(fd, this->recvSizeBuf, BUF_SIZE, 0) == -1)
	{ //接收缓冲区尺寸
		printf("[%s] - Preread error : %s\n", codeName.c_str(), strerror(errno));
		exit(1);
	}
	if (send(fd, this->recvSizeBuf, BUF_SIZE, 0) == -1)
	{ //发送确认信息
		printf("[%s] - Check error : %s\n", codeName.c_str(), strerror(errno));
		exit(1);
	}
	size_t recv_size = stol(this->recvSizeBuf); //接收缓冲区尺寸
	char* cstr = new char[recv_size];           //接收缓冲区
	memset(cstr, '\0', recv_size);
	ssize_t recv_num, remain_num = recv_size;
	clock_t startR = clock();
	while (remain_num > 1)
	{
		if ((recv_num = recv(fd, cstr, recv_size, 0)) == -1 || recv_num == 0)
		{ //接收数据
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

//发送一个string
bool Network::mSend(string send_string)
{
	int fd = (bigMe) ? this->sockCli : sockSer;
	this->mSend(fd, send_string);
	return true;
}

//接收一个string
bool Network::mReceive(string& recv_string)
{
	int fd = (bigMe) ? this->sockCli : sockSer;
	this->mReceive(fd, recv_string);
	return true;
}

//反序列化
void Network::deserialization(string str, vector<string>& strs) {
	size_t pos_start = 0, pos_end = 0;
	while ((pos_end = str.find(delimiter, pos_end)) != string::npos) {
		//pos_end = str.find(delimiter, pos_end);
		strs.push_back(str.substr(pos_start, pos_end - pos_start));
		pos_start = ++pos_end;
	}
}

//发送一个文件
void Network::fSend(string fileName) {
	ifstream ist;
	ist.open(fileName, ios::in);
	if (!ist)
	{
		cout << "Can't open " << fileName << endl;
		exit(1);
	}
	string temp,container;
	while (ist >> temp) {
		container += (temp+"\n");
	}
	ist.close();
	mSend(container);
}

//接收一个文件
void Network::fReceive(string fileName) {
	ofstream ost;
	ost.open(fileName, ios::out);
	if (!ost)
	{
		cout << "Can't creat " << fileName << endl;
		exit(1);
	}
	string  container;
	mReceive(container);
	ost << container;
	ost.close();
}
//关闭套接字
Network::~Network()
{
	if (sockSer)
		close(sockSer);
	if (sockCli)
		close(sockCli);
}