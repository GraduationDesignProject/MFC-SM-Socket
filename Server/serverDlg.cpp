
// serverDlg.cpp : ʵ���ļ�
//

#include "stdafx.h"
#include <sstream>
#include "server.h"
#include "serverDlg.h"
#include "afxdialogex.h"
#include <fstream>

//#include "Mysocket.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif
#include "SM4.h"
#include "ZUC.h"
#include "SM3.h"
#include "SM2SK.h"
#include "SM2Sign.h"
#include "applink.c"

// ����Ӧ�ó��򡰹��ڡ��˵���� CAboutDlg �Ի���

class CAboutDlg : public CDialogEx
{
public:
	CAboutDlg();

// �Ի�������
	enum { IDD = IDD_ABOUTBOX };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV ֧��

// ʵ��
protected:
	DECLARE_MESSAGE_MAP()
};

CAboutDlg::CAboutDlg() : CDialogEx(CAboutDlg::IDD)
{
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialogEx)
END_MESSAGE_MAP()


// CserverDlg �Ի���




CserverDlg::CserverDlg(CWnd* pParent /*=NULL*/)
	: CDialogEx(CserverDlg::IDD, pParent)
	, m_Port(12345)
	, m_strPath(_T("d:\\serverFiles\\"))
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
	m_strMsg = _T("");
}

void CserverDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_LRECVD, m_ctlRecvd);
	DDX_Text(pDX, IDC_EMSG, m_strMsg);
	DDX_Text(pDX, IDC_EMSG_PORT, m_Port);
	DDX_Text(pDX, IDC_EDIT_Path, m_strPath);
}



BEGIN_MESSAGE_MAP(CserverDlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	
	ON_BN_CLICKED(IDC_BSEND, &CserverDlg::OnBnClickedBsend)
	ON_BN_CLICKED(IDC_SERVERSTART, &CserverDlg::OnBnClickedStart)
	ON_BN_CLICKED(IDC_SERVERCLOSE, &CserverDlg::OnBnClickedClose)
	ON_BN_CLICKED(IDC_SERVERSENDFILE, &CserverDlg::OnBnClickedSendFile)
	ON_BN_CLICKED(IDC_SERVERCLOSE2, &CserverDlg::OnBnClickedServerclose2)
	ON_BN_CLICKED(IDC_SERVERCLOSE3, &CserverDlg::OnBnClickedServerclose3)
END_MESSAGE_MAP()


// CserverDlg ��Ϣ�������

BOOL CserverDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// ��������...���˵�����ӵ�ϵͳ�˵��С�

	// IDM_ABOUTBOX ������ϵͳ���Χ�ڡ�
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != NULL)
	{
		BOOL bNameValid;
		CString strAboutMenu;
		bNameValid = strAboutMenu.LoadString(IDS_ABOUTBOX);
		ASSERT(bNameValid);
		if (!strAboutMenu.IsEmpty())
		{
			pSysMenu->AppendMenu(MF_SEPARATOR);
			pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, strAboutMenu);
		}
	}

	// ���ô˶Ի����ͼ�ꡣ��Ӧ�ó��������ڲ��ǶԻ���ʱ����ܽ��Զ�
	//  ִ�д˲���
	SetIcon(m_hIcon, TRUE);			// ���ô�ͼ��
	SetIcon(m_hIcon, FALSE);		// ����Сͼ��

	// TODO: �ڴ���Ӷ���ĳ�ʼ������
	m_sConnectSocket.SetParent(this);
	m_sListenSocket.SetParent(this);


	return TRUE;  // ���ǽ��������õ��ؼ������򷵻� TRUE
}

void CserverDlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	if ((nID & 0xFFF0) == IDM_ABOUTBOX)
	{
		CAboutDlg dlgAbout;
		dlgAbout.DoModal();
	}
	else
	{
		CDialogEx::OnSysCommand(nID, lParam);
	}
}

// �����Ի��������С����ť������Ҫ����Ĵ���
//  �����Ƹ�ͼ�ꡣ����ʹ���ĵ�/��ͼģ�͵� MFC Ӧ�ó���
//  �⽫�ɿ���Զ���ɡ�

void CserverDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // ���ڻ��Ƶ��豸������

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// ʹͼ���ڹ����������о���
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// ����ͼ��
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

//���û��϶���С������ʱϵͳ���ô˺���ȡ�ù��
//��ʾ��
HCURSOR CserverDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}

CString CserverDlg::GetErrorMsg()
{
	LPVOID lpMsgBuf;
	FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER|FORMAT_MESSAGE_FROM_SYSTEM,0, GetLastError(), 
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), //Ĭ������
		(LPTSTR)&lpMsgBuf, 0, NULL );
	//��ʾ
	//MessageBox(0,(LPCTSTR)lpMsgBuf,_T("GetLastError"),MB_OK|MB_ICONINFORMATION );
	CString m_strError;
	m_strError.Format("������룺%d  \n������Ϣ��%s",GetLastError(), (LPCTSTR)lpMsgBuf);
	
	//�ͷ��ڴ�
	::LocalFree( lpMsgBuf );
    return m_strError;
}

void CserverDlg::OnAccept()
{
	//ʹ��m_sConnectSocket���ܣ�������recv
	if (m_sListenSocket.Accept(m_sConnectSocket) == SOCKET_ERROR)
	{
		//������Ϣ���
		CString m_ErrorMsg;
		m_ErrorMsg = GetErrorMsg();
		MessageBox(m_ErrorMsg);
		return;
	}
	else {
		m_sConnectSocket.GetPeerName(client_IP, client_Port);
		CString Client = _T("�ͻ��� ") + _T(client_IP) + _T(" ���ӳɹ���");

		std::ofstream f;

		f.open("data.txt", std::ios::app);

		std::string strIP = client_IP;
		f  << "�ͻ��� " << strIP << " �����ӣ�" << std::endl << std::endl << std::endl;

		f << "������ͻ��˽�����ԿЭ��" << std::endl << std::endl;

		// ʹ�õ�ǰʱ����Ϊ���������
		std::srand(std::time(nullptr));

		// ���������
		int a = std::rand() * 123 % 12345;

		unsigned char sendData[sizeof(int)] = { 0 };
		memcpy(sendData, &a, sizeof(int));
		
		m_sConnectSocket.Send(sendData, sizeof(int));

		Sleep(100);
		unsigned char recvData[sizeof(int)] = { 0 };
		m_sConnectSocket.Receive(recvData, sizeof(int));

		int b;
		memcpy(&b, recvData, sizeof(int));

		extern std::string ShareKey;

		ShareKey = SM2KeyExchange(a, b);

		f << "��ͻ��˵Ĺ�����Կ ShareKey Ϊ: " << ShareKey << std::endl << std::endl;

		f.close();

		AfxMessageBox(Client);
	}
}



void CserverDlg::OnReceive()
{
	std::ofstream f;

	f.open("data.txt", std::ios::app);

	f << std::endl << std::endl << "���ڽ��տͻ�����Ϣ" << std::endl << std::endl;

	char *pBuf = new char[100000]();
	int iBufSize = 99999;
	int iRcvd = m_sConnectSocket.Receive(pBuf,iBufSize);
	CString strRecvd;
	if(iRcvd == SOCKET_ERROR)
	{
		CString m_ErrorMsg;
		m_ErrorMsg = GetErrorMsg();
		MessageBox(m_ErrorMsg);
		return;
	}
	else
	{
		pBuf[iRcvd] = NULL;
		strRecvd = pBuf;
		const int size = 4096;
		//unsigned char SM4key[16] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf, 0x00 };
		unsigned char SM4key[16] = { 0 };
		for (int i(0); i < 16; i++) {
			SM4key[i] = ShareKey[i];
		}
		unsigned char decrypt[size] = { 0 };
		unsigned char out[size] = { 0 };
		unsigned char data[64] = { 0x00 };
		Sleep(300);
		std::string hash = SM3_hash(SM4key, 16);

		int aw(0);
		char sigature[size / 2] = { 0 };
		do {
			aw = m_sConnectSocket.Receive(sigature, 1023);
			if (aw == SOCKET_ERROR) {
				break;
			}
		} while (aw > 0);
	
		f << "�ͻ��������ѽ���" << std::endl << std::endl;
		f << "�ͻ���ǩ���ѽ���" << std::endl << std::endl;


		int pos = strRecvd.ReverseFind('_'); // �ҵ����һ�� "_" ��λ��
		int outLen;
		if (pos >= 0) {
			outLen = _tstoi(strRecvd.Left(pos));
		}

		strcpy_s((char*)out, size, (LPCTSTR)strRecvd.Mid(pos + 1));

		int decryptLen = SM4EncryptDecrypt(out, outLen, decrypt, SM4key, 0);

		const int len = sizeof(decrypt) / sizeof(decrypt[0]);
		CString str((LPCTSTR)decrypt, len);

		std::string sig(sigature, sigature + size / 2);


		int flag = SM2_Verify(hash, sig);

		f <<  "ǩ����֤�ɹ�" << std::endl << std::endl;
		f <<  "���ܳɹ�" << std::endl << std::endl;


		if (str == "aFile")
			recvFile();
		else
		{

			//if (flag == 0 && flagv == 1) {
			if (flag != 0) {
				str = "�ͻ��˶���˵ : " + str;
				f << str << std::endl << std::endl;
				f.close();
			}
			else {
				str = "Verify ERROE";
				f << str << std::endl << std::endl;
				f.close();
			}

			m_ctlRecvd.AddString(str);
		}
		UpdateData(FALSE);
	}
	delete[] pBuf;
}

void CserverDlg::OnClose()
{
    m_sConnectSocket.Close();
}

void CserverDlg::OnBnClickedBsend()
{	
	UpdateData(TRUE);
	if(m_strMsg !="")
	{  
		SendMsg(m_strMsg);
	}
	else {
		AfxMessageBox("���벻�ÿ�");
	}
}

void CserverDlg::SendMsg(CString msg)
{
	std::ofstream f;

	f.open("data.txt", std::ios::app);

	f << std::endl << std::endl << "���ڸ��ͻ��˷�����Ϣ" << std::endl << std::endl;
	CString m_strMessage = msg;
	int iLen = m_strMessage.GetLength();
	const int size = 4096;
	//unsigned char SM4key[16] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf, 0x00 };
	unsigned char SM4key[16] = { 0 };
	for (int i(0); i < 16; i++) {
		SM4key[i] = ShareKey[i];
	}

	unsigned char in[size] = { 0 };
	strcpy_s((char*)in, size, (LPCTSTR)m_strMessage);
	unsigned char out[size] = { 0 };

	int outLen = SM4EncryptDecrypt(in, iLen, out, SM4key, 1);

	iLen = sizeof(out) / sizeof(out[0]);
	CString str((LPCTSTR)out, iLen);

	str = (std::to_string(outLen) + "_").c_str() + str;

	std::string hash = SM3_hash(SM4key, 16);


	size_t sig_len;
	std::string signature = SM2_Sign(hash);

	int iSent = m_sConnectSocket.Send(LPCTSTR(str), str.GetLength());

	Sleep(200);

	hash = SM3_hash(SM4key, 16);


	m_sConnectSocket.Send(signature.c_str(), signature.length());

	f << "�����ѷ��ͳɹ�" << std::endl << std::endl;
	f << "ǩ���ѷ��ͳɹ�" << std::endl << std::endl;

	f.close();
	if (iSent == SOCKET_ERROR)
	{
		CString m_ErrorMsg;
		m_ErrorMsg = GetErrorMsg();
		MessageBox(m_ErrorMsg);
		return;
	}
	else
	{
		if (msg == "aFile")//���������ļ�����ͨ��Ϣ
			return;
		m_strMessage = "���Կͻ���˵: " + m_strMessage;

		m_ctlRecvd.AddString(m_strMessage);

		m_strMsg = "";
		UpdateData(FALSE);
	}
}

void CserverDlg::recvFile()
{
	std::ofstream f;

	f.open("data.txt", std::ios::app);
	f << std::endl << std::endl << "���ڽ��տͻ��˷��͵��ļ�" << std::endl << std::endl;

	AfxSocketInit(NULL);
	CSocket sockClient;
	sockClient.Create();

	CString	szIP = client_IP;

	if (!sockClient.Connect((LPCTSTR)szIP, 9800))
	{
		AfxMessageBox("�Է�δ����");
		return;
	}

	SOCKET_STREAM_FILE_INFO StreamFileInfo;
	sockClient.Receive(&StreamFileInfo, sizeof(SOCKET_STREAM_FILE_INFO));

	UpdateData(TRUE);
	CString strFolderPath = m_strPath;
	if (!PathFileExists(strFolderPath))//�ļ����Ƿ����
	{
		CreateDirectory(strFolderPath, NULL);//��������ھʹ���
	}
	CString strFileName;
	strFileName.Format("%s", StreamFileInfo.szFileTitle);
	strFileName = strFolderPath + strFileName;
	CFile destFile(strFileName, CFile::modeCreate | CFile::modeWrite | CFile::typeBinary);




	//������Կ
	//unsigned char key[16] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf, 0x00 }; // 128-bit ��Կ

	unsigned char key[16] = { 0 };
	for (int i(0); i < 16; i++) {
		key[i] = ShareKey[i];
	}

	//unsigned char iv[16] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf, 0x00 };
	unsigned char iv[16] = { 0 };
	for (int i(0); i < 16; i++) {
		iv[i] = ShareKey[i];
	}
	unsigned char keystream[10000] = { 0x00 };  // ���ڱ�����Կ��

	char data[2048] = { 0x00 };

	UINT dw = sockClient.Receive(data, 2048);

	std::string hash = SM3_hash(key, 16);


	std::string sig(data, data + 2048);


	int flag = SM2_Verify(hash, sig);


	if (flag != 0) {
		// ��ʼ�� LFSR �Ĵ���״̬

		LFSR lfsr;
		ZUC_Initialization(key, iv, lfsr);
		// ������Կ��
		ZUC_GenerateKeystream(key, 10000, keystream, lfsr);

		UINT dwRead = 0;
		while (dwRead < StreamFileInfo.nFileSizeLow)
		{
			unsigned char* data = new unsigned char[10000]();
			unsigned char* plainttext = new unsigned char[10000]();
			memset(data, 0, 9999);
			UINT dw = sockClient.Receive(data, 9999);

			// ִ�н��ܲ���
			for (int i = 0; i < dw; i++) {
				plainttext[i] = data[i] ^ keystream[i];
			}

			// д����ܺ������
			destFile.Write(plainttext, dw);


			dwRead += dw;
			delete[] data;
			delete[] plainttext;
		}

		f << "�ͻ��������ѽ���" << std::endl << std::endl;
		f << "�ͻ���ǩ���ѽ���" << std::endl << std::endl;

		f << "�ͻ���ǩ����֤�ɹ�" << std::endl << std::endl;
		f << "�ͻ������Ľ��ܳɹ�" << std::endl << std::endl;
		f.close();
		SetFileTime((HANDLE)destFile.m_hFile, &StreamFileInfo.ftCreationTime,
			&StreamFileInfo.ftLastAccessTime, &StreamFileInfo.ftLastWriteTime);
		destFile.Close();

		SetFileAttributes(StreamFileInfo.szFileTitle, StreamFileInfo.dwFileAttributes);

		sockClient.Close();
		m_ctlRecvd.AddString("���յ����ļ�" + strFileName);

		UpdateData(FALSE);
	}
}

void CserverDlg::OnBnClickedStart()
{
	UpdateData(1);
	if (!AfxSocketInit())
	{
		AfxMessageBox(IDP_SOCKETS_INIT_FAILED);
		return ;
	}
	//�����׽��־�������ض��Ķ˿�
	m_sListenSocket.Create(m_Port);
	//��������
	if (m_sListenSocket.Listen() == SOCKET_ERROR)
	{
		//������Ϣ���
		CString m_ErrorMsg;
		m_ErrorMsg = GetErrorMsg();
		MessageBox(m_ErrorMsg);
		return;
	}
	CString str;
	//str.Format("%d", m_Port);
	str = _T("�����������ɹ���");
	AfxMessageBox(str);
	
	GetDlgItem(IDC_SERVERSTART)->EnableWindow(FALSE);
	GetDlgItem(IDC_SERVERCLOSE)->EnableWindow(TRUE);
}


void CserverDlg::OnBnClickedClose()
{
	m_sListenSocket.Close();
	m_sConnectSocket.Close();
	GetDlgItem(IDC_SERVERSTART)->EnableWindow(TRUE);
    GetDlgItem(IDC_SERVERCLOSE)->EnableWindow(FALSE);
}


void CserverDlg::OnBnClickedSendFile()
{
	std::ofstream f;

	f.open("data.txt", std::ios::app);
	f << std::endl << std::endl << "���ڷ����ļ����ͻ���" << std::endl << std::endl;

	CFileDialog	Dlg(TRUE);
	if(Dlg.DoModal()!=IDOK)
		return;
	
	CFile myFile;
	if(!myFile.Open(Dlg.GetPathName(), CFile::modeRead | CFile::typeBinary))
	{
		AfxMessageBox("�ļ�������!");
		return;
	}
	CString strFileName = myFile.GetFileTitle();
	CSocket sockSrvr;
	sockSrvr.Create(8800);

	sockSrvr.Listen();

	m_ctlRecvd.AddString("���ڷ����ļ�" + strFileName);

	UpdateData(FALSE);

	//��ʾ�Է��ڷ����ļ���
	//�ͻ����յ�����Ϣ�󣬴���Connect(IP, 8800)


	const int size = 8192;
	//unsigned char SM4key[16] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf, 0x00 };
	unsigned char SM4key[16] = { 0 };
	for (int i(0); i < 16; i++) {
		SM4key[i] = ShareKey[i];
	}

	std::string m_str = "aFile";

	unsigned char in[size] = { 0 };
	strcpy_s((char*)in, size, m_str.c_str());
	unsigned char out[size] = { 0 };

	int outLen = SM4EncryptDecrypt(in, m_str.length() + 1, out, SM4key, 1);

	int len = sizeof(out) / sizeof(out[0]);
	CString str((LPCTSTR)out, len);

	str = (std::to_string(outLen) + "_").c_str() + str;


	m_sConnectSocket.Send(str, 1000);


	CSocket sockRecv;
	sockSrvr.Accept(sockRecv);

	SOCKET_STREAM_FILE_INFO	StreamFileInfo;
	WIN32_FIND_DATA FindFileData;

	FindClose(FindFirstFile(Dlg.GetPathName(),&FindFileData));
    memset(&StreamFileInfo,0,sizeof(SOCKET_STREAM_FILE_INFO));
	CString strFileTitle = myFile.GetFileTitle();
	strcpy_s(StreamFileInfo.szFileTitle, strFileTitle.GetLength()+1, strFileTitle);
	//ע��һ��Ҫ��1����Ϊ������������"\0"

    StreamFileInfo.dwFileAttributes		=		FindFileData.dwFileAttributes;
    StreamFileInfo.ftCreationTime       =       FindFileData.ftCreationTime;
    StreamFileInfo.ftLastAccessTime     =       FindFileData.ftLastAccessTime;
    StreamFileInfo.ftLastWriteTime      =       FindFileData.ftLastWriteTime;
    StreamFileInfo.nFileSizeHigh        =       FindFileData.nFileSizeHigh;
    StreamFileInfo.nFileSizeLow         =       FindFileData.nFileSizeLow;

	sockRecv.Send(&StreamFileInfo,sizeof(SOCKET_STREAM_FILE_INFO), 0);


	// ������Կ
	//unsigned char key[16] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf, 0x00 }; // 128-bit ��Կ

	unsigned char key[16] = { 0 };
	for (int i(0); i < 16; i++) {
		key[i] = ShareKey[i];
	}

	//unsigned char iv[16] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf, 0x00 };
	unsigned char iv[16] = { 0 };
	for (int i(0); i < 16; i++) {
		iv[i] = ShareKey[i];
	}
	unsigned char keystream[10000] = { 0x00 };  // ���ڱ�����Կ��

	std::string hash = SM3_hash(SM4key, 16);

	std::string sig = SM2_Sign(hash);

	sockRecv.Send(sig.c_str(), sig.length());


	// ��ʼ�� LFSR
	LFSR lfsr;
	ZUC_Initialization(key, iv, lfsr);

	// ������Կ��
	ZUC_GenerateKeystream(key, 10000, keystream, lfsr);

	Sleep(100);
	// ��ȡ�ļ����ݲ����м���
	UINT dwRead = 0;
	while (dwRead < StreamFileInfo.nFileSizeLow)
	{
		unsigned char* data = new unsigned char[10000]();
		unsigned char* ciphertext = new unsigned char[10000]();
		UINT dw = myFile.Read(data, 9999);

		// ִ�м��ܲ���
		for (int i = 0; i < dw; i++) {
			ciphertext[i] = keystream[i] ^ data[i];
		}
		sockRecv.Send(ciphertext, dw);

		dwRead += dw;
		delete[] data;
		delete[] ciphertext;
	}

	myFile.Close();
	sockRecv.Close();

	f << "�ļ�ǩ���ѷ���" << std::endl << std::endl;
	f << "�����ļ��ѷ���" << std::endl << std::endl;
	f.close();

	m_ctlRecvd.AddString((strFileName + "�ļ��������"));
	UpdateData(FALSE);
}





void CserverDlg::OnBnClickedServerclose2()
{
	// TODO: �ڴ���ӿؼ�֪ͨ����������
	UpdateData(1);
	ShellExecute(NULL, "open", m_strPath, NULL, NULL, SW_SHOWNORMAL);
}

void CserverDlg::OnBnClickedServerclose3()
{
	// TODO: �ڴ���ӿؼ�֪ͨ����������
	UpdateData(1);

	CString path = "data.txt";

	ShellExecute(NULL, "open", path, NULL, NULL, SW_SHOWNORMAL);
}