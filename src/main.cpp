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
extern ZZ sk_debug;

int main(int argc, char** argv)
{
	array<int, 2> codes;
	int op;
	switch (argc)
	{
		case 1: {
			cout << "Input your code:" << flush;
			cin >> codes[0];
			cout << "Input your opponent's code:" << flush;
			cin >> codes[1];
			break;
		}
		case 2: {
			//Verify
			cout << "You are Verifier" << endl;
			return 0;
		}
		case 3: {
			codes[0] = atoi(argv[1]);
			codes[1] = atoi(argv[2]);
			break;
		}
		default: {
			cout << "parameters error" << endl;
			return 0;
		}
	}
	SBid sbid;
	sbid.prepare(codes);
	sbid.bid();
	sbid.verify();
	return 0;
}