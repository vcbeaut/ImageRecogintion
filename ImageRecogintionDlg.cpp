
// ImageRecogintionDlg.cpp : 实现文件
//

#include "stdafx.h"
#include "ImageRecogintion.h"
#include "ImageRecogintionDlg.h"
#include "afxdialogex.h"

#include <openssl/evp.h>  
#include <openssl/bio.h>  
#include <openssl/buffer.h> 
#include <string>  
#include <iostream> 

#ifdef _DEBUG
#define new DEBUG_NEW
#endif

char * base64Encode(const char *buffer, int length, bool newLine);
char * base64Decode(char *input, int length, bool newLine);

char * base64Encode(const char *buffer, int length, bool newLine)
{
	BIO *bmem = NULL;
	BIO *b64 = NULL;
	BUF_MEM *bptr;

	b64 = BIO_new(BIO_f_base64());
	if (!newLine) {
		BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
	}
	bmem = BIO_new(BIO_s_mem());
	b64 = BIO_push(b64, bmem);
	BIO_write(b64, buffer, length);
	BIO_flush(b64);
	BIO_get_mem_ptr(b64, &bptr);
	BIO_set_close(b64, BIO_NOCLOSE);

	char *buff = (char *)malloc(bptr->length + 1);
	memcpy(buff, bptr->data, bptr->length);
	buff[bptr->length] = 0;
	BIO_free_all(b64);

	return buff;
}

// base64 解码
char * base64Decode(char *input, int length, bool newLine)
{
	BIO *b64 = NULL;
	BIO *bmem = NULL;
	char *buffer = (char *)malloc(length);
	memset(buffer, 0, length);
	b64 = BIO_new(BIO_f_base64());
	if (!newLine) {
		BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
	}
	bmem = BIO_new_mem_buf(input, length);
	bmem = BIO_push(b64, bmem);
	BIO_read(bmem, buffer, length);
	BIO_free_all(bmem);

	return buffer;
}
// 用于应用程序“关于”菜单项的 CAboutDlg 对话框

class CAboutDlg : public CDialogEx
{
public:
	CAboutDlg();

// 对话框数据
	enum { IDD = IDD_ABOUTBOX };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

// 实现
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


// CImageRecogintionDlg 对话框



CImageRecogintionDlg::CImageRecogintionDlg(CWnd* pParent /*=NULL*/)
	: CDialogEx(CImageRecogintionDlg::IDD, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CImageRecogintionDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CImageRecogintionDlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED(IDOK, &CImageRecogintionDlg::OnBnClickedOk)
END_MESSAGE_MAP()


// CImageRecogintionDlg 消息处理程序

BOOL CImageRecogintionDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// 将“关于...”菜单项添加到系统菜单中。

	// IDM_ABOUTBOX 必须在系统命令范围内。
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

	// 设置此对话框的图标。  当应用程序主窗口不是对话框时，框架将自动
	//  执行此操作
	SetIcon(m_hIcon, TRUE);			// 设置大图标
	SetIcon(m_hIcon, FALSE);		// 设置小图标

	// TODO:  在此添加额外的初始化代码
	CoInitialize(NULL);
	return TRUE;  // 除非将焦点设置到控件，否则返回 TRUE
}

void CImageRecogintionDlg::OnSysCommand(UINT nID, LPARAM lParam)
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

// 如果向对话框添加最小化按钮，则需要下面的代码
//  来绘制该图标。  对于使用文档/视图模型的 MFC 应用程序，
//  这将由框架自动完成。

void CImageRecogintionDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // 用于绘制的设备上下文

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// 使图标在工作区矩形中居中
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// 绘制图标
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

//当用户拖动最小化窗口时系统调用此函数取得光标
//显示。
HCURSOR CImageRecogintionDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}
#include "URLEncode.h"
#import "C:\\Windows\\System32\\winhttp.dll" no_namespace

CString GetMidStrByLAndR(CString& strSrc, CString strLeft, CString strRight)
{
	CString strRet;
	int eIdxBegin = strSrc.Find(strLeft);
	if (eIdxBegin != -1)
	{
		eIdxBegin += strLeft.GetLength();
		int eIdxEnd = strSrc.Find(strRight, eIdxBegin);
		if (eIdxEnd != -1)
		{
			strRet = strSrc.Mid(eIdxBegin, eIdxEnd - eIdxBegin);
			return strRet;
		}
	}

	return strRet;
}

void CImageRecogintionDlg::OnBnClickedOk()
{
	// TODO:  在此添加控件通知处理程序代码
	/*CoInitialize(NULL);
	IWinHttpRequestPtr pHttpReq;
	HRESULT hr;
	hr = pHttpReq.CreateInstance(__uuidof(WinHttpRequest));
	if (FAILED(hr)) return;
	hr = pHttpReq->Open(_T("GET"),_T("https://aip.baidubce.com/oauth/2.0/token?grant_type=client_credentials&client_id=fztdG5qcoVskuztmrcsGXCDs&client_secret=l3GZZdXTXBSrX2eDswbt3usrXAw1tGZi&"));
	if (FAILED(hr)) return;
	hr = pHttpReq->Send();
	if (FAILED(hr)) return;
	_variant_t varRspBody = pHttpReq->GetResponseBody();
	ULONG dataLen = varRspBody.parray->rgsabound[0].cElements;
	char *pContentBuffer = (char *)varRspBody.parray->pvData;*/
	
	
	
	/*CString strCntBuffer;
	strCntBuffer = pContentBuffer;
	strCntBuffer = GetMidStrByLAndR(strCntBuffer, _T("access_token\":\""), _T("\""));*/
	
	
	

	CFile file;
	file.Open(_T(".\\1.jpg"), CFile::modeRead, NULL);
	//file.Read(chfile, 1024 * 100);
	
	CFileStatus status;
	if (file.GetStatus(status))    // virtual member function
	{
		TRACE(_T("File size = %u\n"), status.m_size);
	}
	char *chfile = new char[status.m_size];
	file.Read(chfile, status.m_size);
	file.Close();
	char *encode = base64Encode(chfile, status.m_size, false);
	string encodestr = encode;
	encodestr = UrlEncode(encodestr);
	CString strBody;
	strBody = encodestr.c_str();
	
	IWinHttpRequestPtr pHttpReq;
	HRESULT hr;
	hr = pHttpReq.CreateInstance(__uuidof(WinHttpRequest));
	if (FAILED(hr)) return;
	hr = pHttpReq->Open(_T("POST"),_T("https://aip.baidubce.com/rest/2.0/ocr/v1/general_basic"));
	if (FAILED(hr)) return;
	hr = pHttpReq->SetRequestHeader(_T("Content-Type"), _T("application/x-www-form-urlencoded"));
	CString resultBody;
	resultBody.Format(_T("access_token=24.ebb702784d7f8dcfc45a461686924317.2592000.1528042740.282335-10725201&image=%s"), strBody);
	COleVariant varBody;
	varBody = resultBody;
	hr = pHttpReq->Send(varBody);
	if (FAILED(hr)) return;
	_variant_t varRspBody = pHttpReq->GetResponseBody();
	ULONG dataLen = varRspBody.parray->rgsabound[0].cElements;
	char *pContentBuffer = (char *)varRspBody.parray->pvData;
	CString strCntBuffer;
	strCntBuffer = pContentBuffer;
	CoUninitialize();
	/*char *decode = base64Decode(encode, strlen(encode), false);
	CFile wfile;
	wfile.Open(_T(".\\2.jpg"), CFile::modeCreate | CFile::modeReadWrite, NULL);
	wfile.Write(decode, status.m_size);
	wfile.Close();
	CString encodeStr;
	encodeStr = encode;*/
	//MessageBox(encodeStr);
	/*string testStr = UrlEncode("http://www.convertstring.com/zh_CN/EncodeDecode/UrlEncode");
	CString test;
	test = testStr.c_str();
	MessageBox(test);*/
	//CDialogEx::OnOK();
	
}

