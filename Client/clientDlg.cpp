
// clientDlg.cpp : ʵ���ļ�
//

#include "stdafx.h"
#include "client.h"
#include "clientDlg.h"
#include "afxdialogex.h"
#ifdef _DEBUG
#define new DEBUG_NEW
#endif
#include "SM4.h"
#include "ZUC.h"
#include "SM3.h"
#include "SM2SK.h"
#include "SM2Sign.h"
#include <sstream>
#include <fstream>
#include <iomanip>
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


// CclientDlg �Ի���




CclientDlg::CclientDlg(CWnd* pParent /*=NULL*/)
	: CDialogEx(CclientDlg::IDD, pParent)
	, m_strIPAddress(_T("127.0.0.1"))
	, m_strFolder(_T("d:\\clientFiles\\"))
	, m_Port(12345)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
	m_strMess = _T("");
}

void CclientDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Text(pDX, IDC_EMSG, m_strMess);
	DDX_Control(pDX, IDC_LMSG, m_ctrMessage);
	DDX_Text(pDX, IDC_EDIT_IPADDRESS, m_strIPAddress);
	DDX_Text(pDX, IDC_EDIT_FILEFOLDER, m_strFolder);
	DDX_Text(pDX, IDC_EDIT_PORT, m_Port);
}

BEGIN_MESSAGE_MAP(CclientDlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED(IDC_CLIENTCONNECT, &CclientDlg::OnBnClickedConnect)
	ON_BN_CLICKED(IDC_CLIENTDISCONNECT, &CclientDlg::OnBnClickedDisconnect)
	ON_BN_CLICKED(IDC_CLIENTSEND, &CclientDlg::OnBnClickedClientSend)
	ON_EN_CHANGE(IDC_EMSG, &CclientDlg::OnEnChangeEmsg)
	ON_BN_CLICKED(IDC_CLIENTOPENFOLDER, &CclientDlg::OnBnClickedClientopenfolder)
	ON_BN_CLICKED(IDC_CLIENTOPENFOLDER1, &CclientDlg::OnBnClickedClientopenfolder1)
	ON_LBN_SELCHANGE(IDC_LMSG, &CclientDlg::OnLbnSelchangeLmsg)
	ON_BN_CLICKED(IDC_BUTTON1, &CclientDlg::OnBnClickedButton1)
END_MESSAGE_MAP()


// CclientDlg ��Ϣ�������

BOOL CclientDlg::OnInitDialog()
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

void CclientDlg::OnSysCommand(UINT nID, LPARAM lParam)
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

void CclientDlg::OnPaint()
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
HCURSOR CclientDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}


CString CclientDlg::GetErrorMsg()
{
	LPVOID lpMsgBuf;
	FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER|FORMAT_MESSAGE_FROM_SYSTEM,0, GetLastError(), 
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), //Ĭ������
		(LPTSTR)&lpMsgBuf, 0, NULL );
	//��ʾ
	CString m_strError;
	m_strError.Format("������룺%d  \n������Ϣ��%s",GetLastError(), (LPCTSTR)lpMsgBuf);
	
	//�ͷ��ڴ�
	::LocalFree( lpMsgBuf );
    return m_strError;
}

void CclientDlg::OnBnClickedConnect()
{
	UpdateData(TRUE);
	if (!AfxSocketInit())
	{
		AfxMessageBox(IDP_SOCKETS_INIT_FAILED);
		return;
	}
	m_sConnectSocket.Create();
	int retm = m_sConnectSocket.Connect(m_strIPAddress, m_Port);
	CString s;
	s.Format("%d", retm);
	//AfxMessageBox(s);
	if (retm == SOCKET_ERROR)
	{
		CString m_ErrorMsg;
		m_ErrorMsg = GetErrorMsg();
		MessageBox(m_ErrorMsg);
		return;
	}
	GetDlgItem(IDC_CLIENTCONNECT)->EnableWindow(FALSE);
	GetDlgItem(IDC_CLIENTDISCONNECT)->EnableWindow(TRUE);

	std::ofstream f;

	f.open("data.txt", std::ios::app);

	std::string strIP = m_strIPAddress;
	f << "������IPΪ " << strIP << " �ķ�������" << std::endl << std::endl << std::endl;

	f << "�����������������ԿЭ�� " << std::endl << std::endl;

	unsigned char recvData[sizeof(int)] = { 0 };
	m_sConnectSocket.Receive(recvData, sizeof(int));

	int a;
	memcpy(&a, recvData, sizeof(int));

	// ���������
	std::srand(std::time(nullptr));
	int b = std::rand() * 321 % 12345;

	unsigned char sendData[sizeof(int)];
	memcpy(sendData, &b, sizeof(int));
	m_sConnectSocket.Send(sendData, sizeof(int));


	extern std::string ShareKey;
	ShareKey = SM2KeyExchange(a, b);
	f << "��������Ĺ�����Կ ShareKey Ϊ: " << ShareKey << std::endl << std::endl;

	f.close();
}


void CclientDlg::OnReceive()
{	
	std::ofstream f;

	f.open("data.txt", std::ios::app);
	f << std::endl << std::endl << "���ڽ��շ��������͵���Ϣ" << std::endl << std::endl;

	char *pBuf = new char[1000000];
	int iBufSize = 999999;
	int iRcvd;
	CString strRecvd;
	iRcvd = m_sConnectSocket.Receive(pBuf,iBufSize);
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

		const int size = 8192;
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

		int pos = strRecvd.ReverseFind('_'); // �ҵ����һ�� "_" ��λ��
		int outLen;
		if (pos >= 0) {
			outLen = _tstoi(strRecvd.Left(pos));
		}

		strcpy_s((char*)out, size, (LPCTSTR)strRecvd.Mid(pos + 1));

		int decryptLen = SM4EncryptDecrypt(out, outLen, decrypt, SM4key, 0);

		const int len = sizeof(decrypt) / sizeof(decrypt[0]);
		CString str((LPCTSTR)decrypt, len);

		std::string sig(sigature, sigature + len);

		f << "���������͵������ѽ���" << std::endl << std::endl;
		f << "���������͵�ǩ���ѽ���" << std::endl << std::endl;

		f << "���������͵�ǩ����֤�ɹ�" << std::endl << std::endl;
		f << "���������͵����Ľ��ܳɹ�" << std::endl << std::endl;

		int flag = SM2_Verify(hash, sig);

		if (str == "aFile")
			ReceiveFile();
		else
		{
			
			if (flag != 0) {
				str = "����������˵ : " + str;
				f << str << std::endl << std::endl;
				f.close();
			}
			else {
				str = "Verify ERROR";
				f << str << std::endl << std::endl;
				f.close();
			}
			m_ctrMessage.AddString(str);
		}
		UpdateData(FALSE);
	}
	delete[] pBuf;
}


void CclientDlg::OnBnClickedDisconnect()
{
	m_sConnectSocket.Close();
	GetDlgItem(IDC_CLIENTCONNECT)->EnableWindow(TRUE);
	GetDlgItem(IDC_CLIENTDISCONNECT)->EnableWindow(FALSE);
}


void CclientDlg::OnBnClickedClientSend()
{
	std::ofstream f;

	f.open("data.txt", std::ios::app);
	f << std::endl << std::endl << "���ڸ�������������Ϣ" << std::endl << std::endl;

	int iLen;
	int iSent;
	CString m_strMessage;
	UpdateData(TRUE);
	if(m_strMess !="")
	{  
		m_strMessage = m_strMess;
		iLen = m_strMessage.GetLength();
		
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

		std::string sig = SM2_Sign(hash);

		int iSent = m_sConnectSocket.Send(LPCTSTR(str), str.GetLength());

		Sleep(200);

		hash = SM3_hash(SM4key, 16);


		m_sConnectSocket.Send(sig.c_str(), sig.length());

		f << "���ķ��ͳɹ�" << std::endl << std::endl;
		f << "ǩ�����ͳɹ�" << std::endl << std::endl;
		f.close();

		if (iSent == SOCKET_ERROR)
		{
		
			CString m_ErrorMsg;
			m_ErrorMsg = GetErrorMsg();
			MessageBox(m_ErrorMsg);
		}
		else
		{
			m_strMessage = "���Է�����˵: " + m_strMessage;
			m_ctrMessage.AddString(m_strMessage);
			m_strMess ="";
			UpdateData(FALSE);
		}
	}
}


void CclientDlg::OnEnChangeEmsg()
{
	UpdateData();
}

//ͨ����ť���յ�����Ϣ������������������Ϣ
void CclientDlg::ReceiveFile()
{
	std::ofstream f;

	f.open("data.txt", std::ios::app);
	f << std::endl << std::endl << "���ڽ��շ����������ļ�" << std::endl << std::endl;

	AfxSocketInit(NULL);
	CSocket sockClient;
	sockClient.Create();

	CString	szIP;
	GetDlgItemText(IDC_EDIT_IPADDRESS, szIP);

	if (!sockClient.Connect((LPCTSTR)szIP, 8800))
	{
		AfxMessageBox("�Է�δ����");
		return;
	}

	SOCKET_STREAM_FILE_INFO StreamFileInfo;
	sockClient.Receive(&StreamFileInfo, sizeof(SOCKET_STREAM_FILE_INFO));

	UpdateData(TRUE);
	CString strFolderPath= m_strFolder;
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

	f << "������ǩ���ѽ���" << std::endl << std::endl;
	f << "������ǩ����֤�ɹ�" << std::endl << std::endl;


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


		SetFileTime((HANDLE)destFile.m_hFile, &StreamFileInfo.ftCreationTime,
			&StreamFileInfo.ftLastAccessTime, &StreamFileInfo.ftLastWriteTime);
		destFile.Close();

		f << "�������ļ������ѽ���" << std::endl << std::endl;
		f << "�������ļ������ѽ���" << std::endl << std::endl;
		f.close();

		SetFileAttributes(StreamFileInfo.szFileTitle, StreamFileInfo.dwFileAttributes);

		sockClient.Close();
		m_ctrMessage.AddString("���յ����ļ�" + strFileName);

		UpdateData(FALSE);
	}
	//else {
	//	m_ctrMessage.AddString("��ʶ" + CString(std::to_string(flag).c_str()));
	//}


	
}





void CclientDlg::OnBnClickedClientopenfolder()
{	
	ShellExecute(NULL, "open", m_strFolder, NULL, NULL, SW_SHOWNORMAL);
}

void CclientDlg::OnBnClickedClientopenfolder1()
{
	// TODO: �ڴ���ӿؼ�֪ͨ����������
	UpdateData(1);

	CString path = "data.txt";

	ShellExecute(NULL, "open", path, NULL, NULL, SW_SHOWNORMAL);
}


void CclientDlg::OnLbnSelchangeLmsg()
{
	// TODO: �ڴ���ӿؼ�֪ͨ����������
}


void CclientDlg::OnBnClickedButton1()
{
	std::ofstream f;

	f.open("data.txt", std::ios::app);
	f << std::endl << std::endl << "���ڸ������������ļ�" << std::endl << std::endl;

	// TODO: �ڴ���ӿؼ�֪ͨ����������
	CFileDialog	Dlg(TRUE);
	if (Dlg.DoModal() != IDOK)
		return;

	CFile myFile;
	if (!myFile.Open(Dlg.GetPathName(), CFile::modeRead | CFile::typeBinary))
	{
		AfxMessageBox("�ļ�������!");
		return;
	}
	CString strFileName = myFile.GetFileTitle();
	CSocket sockSrvr;
	sockSrvr.Create(9800);

	sockSrvr.Listen();

	m_ctrMessage.AddString("���ڷ����ļ�" + strFileName);
	UpdateData(FALSE);

	//��ʾ�Է��ڷ����ļ�

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

	m_sConnectSocket.Send(LPCTSTR(str), str.GetLength());

	CSocket sockRecv;
	sockSrvr.Accept(sockRecv);

	SOCKET_STREAM_FILE_INFO	StreamFileInfo;
	WIN32_FIND_DATA FindFileData;

	FindClose(FindFirstFile(Dlg.GetPathName(), &FindFileData));
	memset(&StreamFileInfo, 0, sizeof(SOCKET_STREAM_FILE_INFO));
	CString strFileTitle = myFile.GetFileTitle();
	strcpy_s(StreamFileInfo.szFileTitle, strFileTitle.GetLength() + 1, strFileTitle);
	//ע��һ��Ҫ��1����Ϊ������������"\0"

	StreamFileInfo.dwFileAttributes = FindFileData.dwFileAttributes;
	StreamFileInfo.ftCreationTime = FindFileData.ftCreationTime;
	StreamFileInfo.ftLastAccessTime = FindFileData.ftLastAccessTime;
	StreamFileInfo.ftLastWriteTime = FindFileData.ftLastWriteTime;
	StreamFileInfo.nFileSizeHigh = FindFileData.nFileSizeHigh;
	StreamFileInfo.nFileSizeLow = FindFileData.nFileSizeLow;

	sockRecv.Send(&StreamFileInfo, sizeof(SOCKET_STREAM_FILE_INFO), 0);

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

	f << "ǩ���ѷ���������" << std::endl << std::endl;
	f << "�ļ������ѷ���������" << std::endl << std::endl;
	f.close();

	m_ctrMessage.AddString(strFileName + "�ļ��������");
	UpdateData(FALSE);

}

