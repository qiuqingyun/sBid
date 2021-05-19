/**@mainpage  基于区块链上的隐私竞拍系统
* @section   项目详细描述
* 多个竞拍者参与投标，保证投标金额隐私，经过比较选出最大或最小竞价，允许泄露各方投标的大小关系；每个竞拍者均可作为验证方，验证竞拍过程
*
* @section   隐私要求
* -# 投标密文格式及加密正确性
* -# 比较过程正确性
* -# 混淆正确性
* -# 解密正确性
*
* @section   程序功能
* -# 参数生成：生成用于整个竞拍流程的加密参数，生成文件`parameters.txt`
* -# 竞拍功能：读取参与者的竞拍金额，与另一竞拍参与者的竞拍金额进行加密对比，并生成隐私要求的证明，最后输出比较结果
* -# 验证功能：验证某个竞拍参与者的证明，并输出验证结果
*
* @section   使用方法
* -# 命令行格式: ./sBid <para1> <para2> <para3> <para4>
* -# 参数生成：<para1>置0，无需<para2>,<para3>,<para4>参数
* -# 竞拍功能：<para1>为竞拍参与者的唯一编号，<para2>为另一竞拍参与者的唯一编号，<para3>为当前竞拍轮数，无需<para4>参数
* -# 验证功能：<para1>置0，<para2>为将要验证的竞拍参与者的唯一编号，<para3>为另一竞拍参与者的唯一编号，<para4>为将要验证的竞拍轮数
*
**********************************************************************************
*/

#include "./3sBid/sBid.h"
#include "./3server/server.h"
extern ZZ sk_debug;
extern bool debug;
int main(int argc, char** argv)
{

	int op, ch;
	if (argc == 1)
	{
		if (debug) {
			cout << "Input your code:" << flush;
			array<int, 6> codes;
			cin >> codes[0];
			cout << "Input your opponent's code:" << flush;
			cin >> codes[1];
			cout << "Input round:" << flush;
			cin >> codes[2];
			SBid sbid;
			sbid.prepare(codes);
			sbid.bid();
			sbid.verify();
		}
		else {
			cout << "please input \"./sBid -h\" to learn more" << endl;
		}
	}
	else {
		while ((ch = getopt(argc, argv, "b:v:d:r:gt")) != -1)
		{
			switch (ch)
			{
				case 'b': {
					array<int, 6> codes;
					codes[0] = atoi(optarg);//自己的index
					codes[1] = atoi(argv[optind]);//对方的index
					codes[2] = atoi(argv[optind + 1]);//本轮的round
					codes[3] = atoi(argv[optind + 2]);//自己的lastFinishRound
					codes[4] = atoi(argv[optind + 3]);//对方的lastFinishRound
					codes[5] = atoi(argv[optind + 4]);//0:价低胜 1：价高胜
					string outFile = optarg;
					string errFile = outFile + "_err.log";
					outFile += "_out.log";
					freopen(outFile.c_str(), "a", stdout);
					freopen(errFile.c_str(), "a", stderr);
					setbuf(stdout, NULL);
					SBid sbid;
					sbid.prepare(codes);
					time_t rawtime;
					struct tm* info;
					char buffer[80];
					time(&rawtime);
					info = localtime(&rawtime);
					strftime(buffer, 80, "%Y-%m-%d %H:%M:%S", info);
					cout << "[" << codes[0] << "] - " << "Start at " << buffer << endl;
					clock_t begin = GetTickCount();
					sbid.bid();
					sbid.verify();
					clock_t end = GetTickCount();
					double cTime = (end - begin) / (double)CLOCKS_PER_SEC * 1000;
					time(&rawtime);
					info = localtime(&rawtime);
					strftime(buffer, 80, "%Y-%m-%d %H:%M:%S", info);
					cout << "[" << codes[0] << "] - " << "End at " << buffer << endl;
					cout << "[" << codes[0] << "] - " << "Total time " << cTime << " ms\n" << endl;
					fclose(stdout);
					fclose(stderr);
					break;
				}
				case 'v': {
					//Verify
					array<int, 6> codes;
					codes[0] = atoi(optarg);
					codes[1] = atoi(argv[optind]);
					codes[2] = atoi(argv[optind + 1]);
					string outFile = optarg;
					outFile += "_verify.log";
					freopen(outFile.c_str(), "a", stdout);
					setbuf(stdout, NULL);
					vMode = true;
					SBid sbid;
					sbid.prepare(codes);
					sbid.verify();
					fclose(stdout);
					break;
				}
				case 'g': {//parameters gen
					string outFile = "parameters.log";
					freopen(outFile.c_str(), "a", stdout);
					setbuf(stdout, NULL);
					SBid sbid;
					sbid.parametersGen();
					break;
				}
				case 'r': {
					SBid sbid;
					string outFile = optarg;
					outFile += "_out.log";
					freopen(outFile.c_str(), "a", stdout);
					setbuf(stdout, NULL);
					sbid.registration(optarg);
					fclose(stdout);
					break;
				}
				case 't': {//for test
					/*Server server;
					server.start();*/
					int port = 18000;
					Network network;
					network.start(port);
					network.acceptConnect();
					string connent;
					//string fileName = "proveCompare2-R1.txt";
					//network.fReceive(fileName);
					string fileName = "/home/qqy/projects/sBid/demo/bin/1/files_1/proveCompare2-R1.txt";
					network.fSend(fileName);
					cout << connent << endl;
					break;
				}
				case 'd': {
					array<string, 3> paras;
					paras[0] = optarg;//index
					paras[1] = argv[optind];//ciphrtext file name
					paras[2] = argv[optind + 1];//plaintext file name
					string outFile = optarg;
					outFile += "_out.log";
					freopen(outFile.c_str(), "a", stdout);
					setbuf(stdout, NULL);
					SBid sbid;
					sbid.decrypt(paras);
					fclose(stdout);
					break;
				}
				case '?': {
					printf("unknow option:%c\n", optopt);
					break;
				}
				default: {
					cout << "./sBid -g : Parameter Generation" << endl;
					cout << "./sBid -b : Bidding function" << endl;
					cout << "./sBid -v : Verification function" << endl;
					break;
				}
			}
		}
	}
	return 0;
}