package behaviors

import "regexp"

// BehaviorTag is a high-level behavioral classification.
type BehaviorTag string

const (
	TagNetwork   BehaviorTag = "NETWORK"
	TagCrypto    BehaviorTag = "CRYPTO"
	TagFileWrite BehaviorTag = "FILE_WRITE"
	TagFileRead  BehaviorTag = "FILE_READ"
	TagExecution BehaviorTag = "EXECUTION"
	TagRegistry  BehaviorTag = "REGISTRY"
	TagMemory    BehaviorTag = "MEMORY"
	TagDNS       BehaviorTag = "DNS"
	TagHTTP      BehaviorTag = "HTTP"
)

// TagRule defines when a tag applies to a function.
type TagRule struct {
	Tag         BehaviorTag
	CallTargets []string       // tag applies if function calls any of these (prefix match)
	StringPat   *regexp.Regexp // OR if function references a string matching this pattern
}

// tagRules is the static rule set applied to all functions.
var tagRules = []TagRule{
	{
		Tag: TagHTTP,
		CallTargets: []string{
			"net/http.(*Client).Do",
			"net/http.(*Client).Get",
			"net/http.(*Client).Post",
			"net/http.Get",
			"net/http.Post",
			"net/http.(*Transport).roundTrip",
			"net/http.(*Server).ListenAndServe",
		},
		StringPat: regexp.MustCompile(`(?i)(https?://|http\.Handle|ListenAndServe)`),
	},
	{
		Tag: TagNetwork,
		CallTargets: []string{
			"net.(*Dialer).DialContext",
			"net.(*TCPConn).Write",
			"net.(*UDPConn).Write",
			"net.Dial",
			"net.Listen",
			"net.ResolveTCPAddr",
			"net.(*TCPListener).Accept",
			"syscall.Connect",
			"syscall.Bind",
			"syscall.Listen",
		},
		StringPat: regexp.MustCompile(`(?i)(tcp:|udp:|:80\b|:443\b|:8080\b|:8443\b)`),
	},
	{
		Tag: TagDNS,
		CallTargets: []string{
			"net.LookupHost",
			"net.LookupAddr",
			"net.LookupMX",
			"net.LookupTXT",
			"net.(*Resolver).LookupHost",
		},
	},
	{
		Tag: TagCrypto,
		CallTargets: []string{
			"crypto/aes.",
			"crypto/des.",
			"crypto/rsa.",
			"crypto/ecdsa.",
			"crypto/sha256.",
			"crypto/sha512.",
			"crypto/md5.",
			"crypto/hmac.",
			"crypto/tls.",
			"crypto/rand.",
			"golang.org/x/crypto/bcrypt.",
			"golang.org/x/crypto/pbkdf2.",
			"golang.org/x/crypto/nacl.",
		},
		StringPat: regexp.MustCompile(`(?i)(AES|RSA|SHA-?256|HMAC|encrypt|decrypt|cipher)`),
	},
	{
		Tag: TagFileWrite,
		CallTargets: []string{
			"os.Create",
			"os.OpenFile",
			"os.(*File).Write",
			"os.(*File).WriteString",
			"io/ioutil.WriteFile",
			"bufio.(*Writer).Flush",
			"os.WriteFile",
		},
	},
	{
		Tag: TagFileRead,
		CallTargets: []string{
			"os.Open",
			"os.ReadFile",
			"io/ioutil.ReadFile",
			"os.(*File).Read",
			"bufio.(*Reader).ReadString",
		},
	},
	{
		Tag: TagExecution,
		CallTargets: []string{
			"os/exec.(*Cmd).Run",
			"os/exec.(*Cmd).Start",
			"os/exec.(*Cmd).Output",
			"os/exec.(*Cmd).CombinedOutput",
			"syscall.Exec",
			"os.StartProcess",
		},
	},
	{
		Tag: TagRegistry,
		CallTargets: []string{
			"golang.org/x/sys/windows/registry.",
			"syscall.RegOpenKeyEx",
			"syscall.RegSetValueEx",
		},
		StringPat: regexp.MustCompile(`(?i)(HKEY_|SOFTWARE\\|SYSTEM\\|CurrentVersion)`),
	},
	{
		Tag: TagMemory,
		CallTargets: []string{
			"syscall.Mmap",
			"syscall.VirtualAlloc",
			"syscall.VirtualProtect",
			"golang.org/x/sys/windows.VirtualAlloc",
			"golang.org/x/sys/windows.VirtualProtect",
		},
	},
}
