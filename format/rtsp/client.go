package rtsp

import (
	"bufio"
	"bytes"
	"crypto/md5"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/nareix/joy4/utils/bits/pio"
	"github.com/nareix/joy4/av"
	"github.com/nareix/joy4/av/avutil"
	"github.com/nareix/joy4/codec"
	"github.com/nareix/joy4/codec/aacparser"
	"github.com/nareix/joy4/codec/codecparser"
	"github.com/nareix/joy4/codec/h264parser"
	"github.com/nareix/joy4/format/rtsp/sdp"
	"io"
	"net"
	"net/textproto"
	"net/url"
	"strconv"
	"strings"
	"time"
)

var ErrCodecDataChange = fmt.Errorf("rtsp: codec data change, please call HandleCodecDataChange()")

var DebugRtp = false
var DebugRtsp = false
var SkipErrRtpBlock = false

const (
	stageDescribeDone = iota+1
	stageSetupDone
	stageWaitCodecData
	stageCodecDataDone
)
const (
	RtpFlagMarker = 0x2 // RTP marker bit was set for this packet
)

type Client struct {
	DebugRtsp bool
	DebugRtp bool
	Headers   []string

	SkipErrRtpBlock bool

	RtspTimeout          time.Duration
	RtpTimeout           time.Duration
	RtpKeepAliveTimeout  time.Duration
	rtpKeepaliveTimer    time.Time
	rtpKeepaliveEnterCnt int

	stage int

	setupIdx    []int
	setupMap    []int

	authHeaders func(method string) []string

	url        *url.URL
	conn       *connWithTimeout
	brconn      *bufio.Reader
	requestUri string
	cseq       uint
	streams    []*Stream
	streamsintf []av.CodecData
	session     string
	body        io.Reader

	RtspUDP bool
	RtpCon  []*net.UDPConn
	RtspCon []*net.UDPConn

	channelMap map[int]int

	PublicOptions map[string]bool

	RtspOverHTTP       bool
	connForOverHTTP    *connWithTimeoutBase64
	brconn2ForOverHTTP *bufio.Reader
}

type Request struct {
	Header []string
	Uri    string
	Method string
}

type Response struct {
	StatusCode    int
	Headers        textproto.MIMEHeader
	ContentLength int
	Body          []byte

	Block []byte
}

func DialTimeout(uri string, timeout time.Duration) (self *Client, err error) {
	var URL *url.URL
	if URL, err = url.Parse(uri); err != nil {
		return
	}

	RtspOverHTTP := false
	if URL.Scheme == "rtsphttp" {
		RtspOverHTTP = true
		URL.Scheme = "rtsp"
	}

	if _, _, err := net.SplitHostPort(URL.Host); err != nil {
		URL.Host = URL.Host + ":554"
	}

	dailer := net.Dialer{Timeout: timeout}
	var conn net.Conn
	if conn, err = dailer.Dial("tcp", URL.Host); err != nil {
		return
	}

	u2 := *URL
	u2.User = nil

	connt := &connWithTimeout{Conn: conn}

	self = &Client{
		conn:            connt,
		brconn:          bufio.NewReaderSize(connt, 256),
		url:             URL,
		requestUri:      u2.String(),
		DebugRtp:        DebugRtp,
		DebugRtsp:       DebugRtsp,
		SkipErrRtpBlock: SkipErrRtpBlock,
		channelMap:      map[int]int{},
		PublicOptions:   map[string]bool{},
	}

	if RtspOverHTTP {
		if err = self.PrepareHTTPTunnel(timeout); err != nil {
			return
		}
	}

	return
}

func (self *Client) PrepareHTTPTunnel(timeout time.Duration) (err error) {
	self.RtspOverHTTP = true
	req := &http.Request{
		ProtoMajor: 1,
		ProtoMinor: 1,
		Method:     "GET",
		URL:        self.url,
		Header:     make(http.Header),
	}
	session := uuid.Must(uuid.NewV4()).String()
	req.Header.Add("User-Agent", "smartconnector/1.0")
	req.Header.Add("Range", "bytes=0-")
	req.Header.Add("Icy-MetaData", "1")
	req.Header.Add("Accept", "application/x-rtsp-tunnelled")
	req.Header.Add("Pragma", "no-cache")
	req.Header.Add("Connection", "close")
	req.Header.Add("Cache-Control", "no-cache")
	req.Header["x-sessioncookie"] = []string{session}

	if self.url.User != nil {
		usr := self.url.User.Username()
		pwd, _ := self.url.User.Password()
		if pwd != "" {
			req.SetBasicAuth(usr, pwd)
		}
	}
	reqHeader, err := httputil.DumpRequest(req, false)
	if err != nil {
		return err
	}
	if self.DebugRtsp {
		data, _ := httputil.DumpRequest(req, false)
		if data != nil {
			fmt.Println(">", "[["+string(data)+"]]")
		}
	}

	conreq := &http.Request{
		ProtoMajor: 1,
		ProtoMinor: 1,
		Method:     "POST",
		URL:        self.url,
		Header:     make(http.Header),
	}
	conreq.Header.Add("User-Agent", "smartconnector/1.0")
	conreq.Header.Add("Icy-MetaData", "1")
	conreq.Header.Add("Accept", "*/*")
	conreq.Header.Add("Content-Type", "application/x-rtsp-tunnelled")
	conreq.Header.Add("Pragma", "no-cache")
	conreq.Header.Add("Connection", "close")
	conreq.Header.Add("Cache-Control", "no-cache")
	conreq.Header.Add("Content-Length", "32767")
	conreq.Header.Add("Expires", "Sun, 9 Jan 1972 00:00:00 GMT")
	conreq.Header["x-sessioncookie"] = []string{session}

	if self.url.User != nil {
		usr := self.url.User.Username()
		pwd, _ := self.url.User.Password()
		if pwd != "" {
			conreq.SetBasicAuth(usr, pwd)
		}
	}
	conreqHeader, err := httputil.DumpRequest(conreq, false)
	if err != nil {
		return err
	}
	if self.DebugRtsp {
		data, _ := httputil.DumpRequest(conreq, false)
		if data != nil {
			fmt.Println(">", "[["+string(data)+"]]")
		}
	}

	if _, err = self.conn.Write(reqHeader); err != nil {
		return
	}
	var res *http.Response
	// var v http.Response
	if res, err = http.ReadResponse(self.brconn, req); err != nil {
		return
	}

	// do not read res.Body or connection closed
	// var body []byte
	// if body, err = ioutil.ReadAll(res.Body); err != nil {
	// 	return err
	// }

	if self.DebugRtsp {
		fmt.Println("<")
		fmt.Println(res.StatusCode, res.Status)
	}

	if res.StatusCode != 200 {
		err = errors.New(res.Status)
	}

	dailer := net.Dialer{Timeout: timeout}
	var conn net.Conn
	if conn, err = dailer.Dial("tcp", self.url.Host); err != nil {
		return
	}

	connt := &connWithTimeoutBase64{Conn: conn}

	self.connForOverHTTP = connt
	self.brconn2ForOverHTTP = bufio.NewReaderSize(connt, 256)

	if _, err = self.connForOverHTTP.WriteRaw(conreqHeader); err != nil {
		return
	}

	return
}

func Dial(uri string) (self *Client, err error) {
	return DialTimeout(uri, 0)
}

func (self *Client) allCodecDataReady() bool {
	for _, si:= range self.setupIdx {
		stream := self.streams[si]
		if stream.Sdp.AVType == "application" {
			continue
		}
		if stream.Sdp.AVType == "audio" {
			continue
		}
		if stream.CodecData == nil {
			return false
		}
	}
	return true
}

func (self *Client) probe() (err error) {
	begin := time.Now()

	for {
		if self.allCodecDataReady() {
			break
		}
		if _, err = self.readPacket(); err != nil {
			return
		}

		if time.Now().Add(-time.Second * 30).After(begin) {
			err = errors.New("Close by timeout in probe")
			return
		}
	}
	self.stage = stageCodecDataDone
	return
}

func (self *Client) prepare(stage int) (err error) {
	for self.stage < stage {
		switch self.stage {
		case 0:
			self.Options()
			if _, err = self.Describe(); err != nil {
				return
			}

		case stageDescribeDone:
			if err = self.SetupAll(); err != nil {
				return
			}

		case stageSetupDone:
			if err = self.Play(); err != nil {
				return
			}

		case stageWaitCodecData:
			if err = self.probe(); err != nil {
				return
			}
		}
	}
	return
}

func (self *Client) Streams() (streams []av.CodecData, err error) {
	if err = self.prepare(stageCodecDataDone); err != nil {
		return
	}
	for _, si := range self.setupIdx {
		stream := self.streams[si]
		streams = append(streams, stream.CodecData)
	}
	return
}

func (self *Client) SendRtpKeepalive() (err error) {
	if self.RtpKeepAliveTimeout > 0 {
		if self.rtpKeepaliveTimer.IsZero() {
			self.rtpKeepaliveTimer = time.Now()
		} else if time.Now().Sub(self.rtpKeepaliveTimer) > self.RtpKeepAliveTimeout {
			self.rtpKeepaliveTimer = time.Now()
			if self.DebugRtsp {
				fmt.Println("rtp: keep alive")
			}
			if val, ok := self.PublicOptions["GET_PARAMETER"]; ok && val {
				req := Request{
					Method: "GET_PARAMETER",
					Uri:    self.requestUri,
				}
				if self.session != "" {
					req.Header = append(req.Header, "Session: "+self.session)
				}
				if err = self.WriteRequest(req); err != nil {
					return
				}
			} else {
				req := Request{
					Method: "OPTIONS",
					Uri:    self.requestUri,
				}
				if err = self.WriteRequest(req); err != nil {
					return
				}
			}
		}
	}
	return
}

func (self *Client) WriteRequest(req Request) (err error) {
	if self.RtspOverHTTP {
		self.connForOverHTTP.Timeout = self.RtspTimeout
	} else {
		self.conn.Timeout = self.RtspTimeout
	}
	self.cseq++

	buf := &bytes.Buffer{}

	fmt.Fprintf(buf, "%s %s RTSP/1.0\r\n", req.Method, req.Uri)
	fmt.Fprintf(buf, "CSeq: %d\r\n", self.cseq)

	if self.authHeaders != nil {
		headers := self.authHeaders(req.Method, req.Uri)
		for _, s := range headers {
			io.WriteString(buf, s)
			io.WriteString(buf, "\r\n")
		}
	}
	for _, s := range req.Header {
		io.WriteString(buf, s)
		io.WriteString(buf, "\r\n")
	}
	for _, s := range self.Headers {
		io.WriteString(buf, s)
		io.WriteString(buf, "\r\n")
	}
	io.WriteString(buf, "\r\n")

	bufout := buf.Bytes()

	if self.DebugRtsp {
		fmt.Print("> ", string(bufout))
	}

	if self.RtspOverHTTP {
		if _, err = self.connForOverHTTP.Write(bufout); err != nil {
			return
		}
	} else {
		if _, err = self.conn.Write(bufout); err != nil {
			return
		}
	}

	return
}

func (self *Client) parseBlockHeader(h []byte) (length int, no int, valid bool) {
	length = int(h[2])<<8 + int(h[3])
	no = int(h[1])
	no = self.channelMap[no]
	if no/2 >= len(self.streams) {
		return
	}

	if no%2 == 0 { // rtp
		if length < 8 {
			return
		}

		// V=2
		if h[4]&0xc0 != 0x80 {
			return
		}

		stream := self.streams[no/2]
		if int(h[5]&0x7f) != stream.Sdp.PayloadType {
			return
		}

		timestamp := binary.BigEndian.Uint32(h[8:12])
		if stream.firsttimestamp != 0 {
			timestamp -= stream.firsttimestamp
			if timestamp < stream.timestamp {
				return
			} else if timestamp-stream.timestamp > uint32(stream.timeScale()*60*60) {
				return
			}
		}
	} else { // rtcp
	}

	valid = true
	return
}

func (self *Client) parseHeaders(b []byte) (statusCode int, headers textproto.MIMEHeader, err error) {
	var line string
	r := textproto.NewReader(bufio.NewReader(bytes.NewReader(b)))
	if line, err = r.ReadLine(); err != nil {
		err = fmt.Errorf("rtsp: header invalid")
		return
	}

	if codes := strings.Split(line, " "); len(codes) >= 2 {
		if statusCode, err = strconv.Atoi(codes[1]); err != nil {
			err = fmt.Errorf("rtsp: header invalid: %s", err)
			return
		}
	}

	headers, _ = r.ReadMIMEHeader()
	return
}

func (self *Client) handleResp(res *Response) (err error) {
	if sess := res.Headers.Get("Session"); sess != "" && self.session == "" {
		if fields := strings.Split(sess, ";"); len(fields) > 0 {
			self.session = fields[0]
		}
	}
	if res.StatusCode == 401 {
		if err = self.handle401(res); err != nil {
			return
		}
	}
	return
}

func (self *Client) handle401(res *Response) (err error) {
	/*
		RTSP/1.0 401 Unauthorized
		CSeq: 2
		Date: Wed, May 04 2016 10:10:51 GMT
		WWW-Authenticate: Digest realm="LIVE555 Streaming Media", nonce="c633aaf8b83127633cbe98fac1d20d87"
	*/
	authval := ""
	if res.Headers[textproto.CanonicalMIMEHeaderKey("WWW-Authenticate")] != nil {
		for _, _authval := range res.Headers[textproto.CanonicalMIMEHeaderKey("WWW-Authenticate")] {
			if _authval != "" && strings.HasPrefix(_authval, "Basic ") {
				authval = _authval
			}
			if strings.HasPrefix(_authval, "Digest ") {
				authval = _authval
			}
		}
	}
	// authval := res.Headers.Get("WWW-Authenticate")
	hdrval := strings.SplitN(authval, " ", 2)
	var realm, nonce string

	if len(hdrval) == 2 {
		for n, field := range strings.Split(hdrval[1], ",") {
			field = strings.Trim(field, ", ")
			if n == 0 { // realm
				keyval := strings.Split(field, "realm=")
				val := strings.Trim(keyval[1], `"`)
				if len(keyval) == 2 {
					realm = val
				}
			} else if n == 1 { // nonce
				keyval := strings.Split(field, "nonce=")
				val := strings.Trim(keyval[1], `"`)
				if len(keyval) == 2 {
					nonce = val
				}
			}
		}

		if realm != "" {
			var username string
			var password string

			if self.url.User == nil {
				err = fmt.Errorf("rtsp: no username")
				return
			}
			username = self.url.User.Username()
			password, _ = self.url.User.Password()

			self.authHeaders = func(method string, uri string) []string {
				var headers []string
				if nonce == "" {
					headers = []string{
						fmt.Sprintf(`Authorization: Basic %s`, base64.StdEncoding.EncodeToString([]byte(username+":"+password))),
					}
				} else {
					hs1 := md5hash(username + ":" + realm + ":" + password)
					hs2 := md5hash(method + ":" + uri)
					response := md5hash(hs1 + ":" + nonce + ":" + hs2)
					headers = []string{fmt.Sprintf(
						`Authorization: Digest username="%s", realm="%s", nonce="%s", uri="%s", response="%s"`,
						username, realm, nonce, uri, response)}
				}
				return headers
			}
		}
	}

	return
}

func (self *Client) findRTSP() (block []byte, data []byte, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = errors.New(fmt.Sprintf("run time panic: %v", r))
		}
	}()

	const (
		R = iota + 1
		T
		S
		Header
		Dollar
	)
	var _peek [8]byte
	peek := _peek[0:0]
	stat := 0

	begin := time.Now()

	for i := 0; ; i++ {
		var b byte
		if b, err = self.brconn.ReadByte(); err != nil {
			return
		}
		switch b {
		case 'R':
			if stat == 0 {
				stat = R
			}
		case 'T':
			if stat == R {
				stat = T
			}
		case 'S':
			if stat == T {
				stat = S
			}
		case 'P':
			if stat == S {
				stat = Header
			}
		case '$':
			if stat != Dollar {
				stat = Dollar
				peek = _peek[0:0]
			}
		default:
			if stat != Dollar {
				stat = 0
				peek = _peek[0:0]
			}
		}

		if false && self.DebugRtp {
			fmt.Println("rtsp: findRTSP", i, b)
		}

		if stat != 0 {
			peek = append(peek, b)
		}
		if stat == Header {
			data = peek
			return
		}

		if stat == Dollar && len(peek) >= 12 {
			if self.DebugRtp {
				fmt.Println("rtsp: dollar at", i, len(peek))
			}
			if blocklen, _, ok := self.parseBlockHeader(peek); ok {
				left := blocklen + 4 - len(peek)
				block = append(peek, make([]byte, left)...)
				if _, err = io.ReadFull(self.brconn, block[len(peek):]); err != nil {
					return
				}
				return
			}
			stat = 0
			peek = _peek[0:0]
		}

		if time.Now().Add(-time.Second * 30).After(begin) {
			err = errors.New("Close by timeout in findRTSP")
			return
		}
	}

	return
}

func (self *Client) readLFLF() (block []byte, data []byte, err error) {
	const (
		LF = iota + 1
		LFLF
	)
	peek := []byte{}
	stat := 0
	dollarpos := -1
	lpos := 0
	pos := 0

	begin := time.Now()

	for {
		var b byte
		if b, err = self.brconn.ReadByte(); err != nil {
			return
		}
		switch b {
		case '\n':
			if stat == 0 {
				stat = LF
				lpos = pos
			} else if stat == LF {
				if pos-lpos <= 2 {
					stat = LFLF
				} else {
					lpos = pos
				}
			}
		case '$':
			dollarpos = pos
		}
		peek = append(peek, b)

		if stat == LFLF {
			data = peek
			return
		} else if dollarpos != -1 && dollarpos-pos >= 12 {
			hdrlen := dollarpos - pos
			start := len(peek) - hdrlen
			if blocklen, _, ok := self.parseBlockHeader(peek[start:]); ok {
				block = append(peek[start:], make([]byte, blocklen+4-hdrlen)...)
				if _, err = io.ReadFull(self.brconn, block[hdrlen:]); err != nil {
					return
				}
				return
			}
			dollarpos = -1
		}

		pos++

		if time.Now().Add(-time.Second * 30).After(begin) {
			err = errors.New("Close by timeout in readLFLF")
			return
		}
	}

	return
}

func (self *Client) readResp(b []byte) (res Response, err error) {
	if res.StatusCode, res.Headers, err = self.parseHeaders(b); err != nil {
		return
	}
	res.ContentLength, _ = strconv.Atoi(res.Headers.Get("Content-Length"))
	if res.ContentLength > 0 {
		res.Body = make([]byte, res.ContentLength)
		if _, err = io.ReadFull(self.brconn, res.Body); err != nil {
			return
		}
	}
	if err = self.handleResp(&res); err != nil {
		return
	}
	return
}

func (self *Client) poll() (res Response, err error) {
	var block []byte
	var rtsp []byte
	var headers []byte

	self.conn.Timeout = self.RtspTimeout
	for {
		if block, rtsp, err = self.findRTSP(); err != nil {
			return
		}
		if len(block) > 0 {
			res.Block = block
			return
		} else {
			if block, headers, err = self.readLFLF(); err != nil {
				return
			}
			if len(block) > 0 {
				res.Block = block
				return
			}
			if res, err = self.readResp(append(rtsp, headers...)); err != nil {
				return
			}
		}
		return
	}

	return
}

func (self *Client) ReadResponse() (res Response, err error) {
	begin := time.Now()
	for {
		if res, err = self.poll(); err != nil {
			return
		}
		if res.StatusCode > 0 {
			return
		}
		if time.Now().Add(-time.Second * 30).After(begin) {
			err = errors.New("Close by timeout in ReadResponse")
			return
		}
	}
	return
}

func (self *Client) SetupAll() (err error) {
	idx := []int{}
	for i := range self.streams {
		idx = append(idx, i)
	}
	return self.Setup(idx)
}

func (self *Client) Setup(idx []int) (err error) {
	var res Response
	if err = self.prepare(stageDescribeDone); err != nil {
		return
	}

	rtpPort := 8000
	rtspPort := 8001

	self.setupMap = make([]int, len(self.streams))
	self.RtpCon = make([]*net.UDPConn, len(idx))
	self.RtspCon = make([]*net.UDPConn, len(idx))
	for i := range self.setupMap {
		self.setupMap[i] = -1
	}
	self.setupIdx = idx

	for i, si := range idx {
		self.setupMap[si] = i

		uri := ""
		control := self.streams[si].Sdp.Control
		if strings.HasPrefix(control, "rtsp://") {
			uri = control
		} else {
			uri = self.requestUri + "/" + control
		}
		req := Request{Method: "SETUP", Uri: uri}
		if self.RtspUDP {
			for j := 0; j < 100; j++ {
				rtpPort += 2
				rtspPort += 2
				{
					addr := net.UDPAddr{
						Port: rtpPort,
						IP:   net.ParseIP("0.0.0.0"),
					}
					self.RtpCon[i], err = net.ListenUDP("udp", &addr)
					fmt.Println(err)
					if err != nil {
						continue
					}
				}

				{
					addr := net.UDPAddr{
						Port: rtspPort,
						IP:   net.ParseIP("0.0.0.0"),
					}
					self.RtspCon[i], err = net.ListenUDP("udp", &addr)
					fmt.Println(err)
					if err != nil {
						self.RtpCon[i].Close()
						self.RtpCon[i] = nil
						continue
					}
				}
				break
			}
			req.Header = append(req.Header, fmt.Sprintf("Transport: RTP/AVP;unicast;client_port=%d-%d", rtpPort, rtspPort))
		} else {
			req.Header = append(req.Header, fmt.Sprintf("Transport: RTP/AVP/TCP;unicast;interleaved=%d-%d", si*2, si*2+1))
		}
		if self.session != "" {
			req.Header = append(req.Header, "Session: "+self.session)
		}
		if err = self.WriteRequest(req); err != nil {
			return
		}
		if res, err = self.ReadResponse(); err != nil {
			return
		}
		body := string(res.Body)
		self.channelMap[si*2] = si * 2
		self.channelMap[si*2+1] = si*2 + 1
		transport := res.Headers.Get("Transport")
		if len(transport) > 0 {
			var interleaved = regexp.MustCompile(`interleaved=([0-9]*)-([0-9]*)`)
			val := interleaved.FindStringSubmatch(transport)
			if len(val) == 2 {
				self.channelMap[si*2], err = strconv.Atoi(val[0])
				self.channelMap[si*2+1], err = strconv.Atoi(val[1])
				self.setupMap[si*2] = self.channelMap[si*2]
				self.setupMap[si*2+1] = self.channelMap[si*2+1]
			}
		}

		if int(res.StatusCode/100) == 4 {
			err = fmt.Errorf("%v : error code %v", res.Headers.Get("Server"), res.StatusCode)
			return
		}
		if self.DebugRtsp {
			fmt.Println("<", res.StatusCode, body)
		}

	}

	if self.stage == stageDescribeDone {
		self.stage = stageSetupDone
	}
	return
}

func md5hash(s string) string {
	h := md5.Sum([]byte(s))
	return hex.EncodeToString(h[:])
}

func (self *Client) Describe() (streams []sdp.Media, err error) {
	var res Response

	for i := 0; i < 2; i++ {
		req := Request{
			Method: "DESCRIBE",
			Uri:    self.requestUri,
			Header: []string{"Accept: application/sdp"},
		}
		if err = self.WriteRequest(req); err != nil {
			return
		}
		if res, err = self.ReadResponse(); err != nil {
			return
		}
		if res.StatusCode == 200 {
			break
		}
	}
	if res.ContentLength == 0 {
		err = fmt.Errorf("rtsp: Describe failed, StatusCode=%d", res.StatusCode)
		return
	}

	body := string(res.Body)

	if self.DebugRtsp {
		fmt.Println("<", body)
	}

	_, medias := sdp.Parse(body)

	/// Content-Base 가 있는경우, requestUri 변경
	// 우선순위
	//  1. control 에 rtsp 주소가 있을경우,
	//  2. control 에 rtsp 주소가 없을경우, Content-Base + control
	if val, ok := res.Headers["Content-Base"]; ok {
		fmt.Print(val)
		if len(val) > 0 {
			self.requestUri = val[0]
			if self.requestUri[len(self.requestUri)-1] == '/' {
				self.requestUri = self.requestUri[:len(self.requestUri)-1]
			}
		}
	}
	///

	self.streams = []*Stream{}
	for _, media := range medias {
		stream := &Stream{Sdp: media, client: self}
		stream.makeCodecData()
		self.streams = append(self.streams, stream)
		streams = append(streams, media)
	}

	if self.stage == 0 {
		self.stage = stageDescribeDone
	}
	return
}

func (self *Client) Options() (err error) {
	req := Request{
		Method: "OPTIONS",
		Uri:    self.requestUri,
	}
	if self.session != "" {
		req.Header = append(req.Header, "Session: "+self.session)
	}
	if err = self.WriteRequest(req); err != nil {
		return
	}
	var res Response
	if res, err = self.ReadResponse(); err != nil {
		fmt.Println(err)
		return
	}
	options := strings.Split(strings.ReplaceAll(res.Headers.Get("Public"), " ", ""), ",")
	for _, opt := range options {
		self.PublicOptions[opt] = true
	}
	if self.DebugRtsp {
		fmt.Println(string(res.Body))
	}
	return
}

func (self *Client) IsCodecDataChange() bool {
	for _, stream := range self.streams {
		if stream != nil && stream.isCodecDataChange() {
			return true
		}
	}
	return false
}

func (self *Client) HandleCodecDataChange() error {
	for i, _ := range self.streams {
		if self.streams[i] != nil {
			if self.streams[i].isCodecDataChange() {
				err := self.streams[i].makeCodecData()
				if err != nil {
					return err
				}
				self.streams[i].clearCodecDataChange()
			}
		}
	}
	return nil
}

// func (self *Client) HandleCodecDataChange() (_newcli *Client, err error) {
// 	newcli := &Client{}
// 	*newcli = *self

// 	newcli.streams = []*Stream{}
// 	for _, stream := range self.streams {
// 		newstream := &Stream{}
// 		*newstream = *stream
// 		newstream.client = newcli

// 		if newstream.isCodecDataChange() {
// 			if err = newstream.makeCodecData(); err != nil {
// 				return
// 			}
// 			newstream.clearCodecDataChange()
// 		}
// 		newcli.streams = append(newcli.streams, newstream)
// 	}

// 	_newcli = newcli
// 	return
// }

func (self *Stream) clearCodecDataChange() {
	self.spsChanged = false
	self.ppsChanged = false
}

func (self *Stream) isCodecDataChange() bool {
	if self.spsChanged && self.ppsChanged {
		return true
	}
	return false
}

func (self *Stream) timeScale() int {
	t := self.Sdp.TimeScale
	if t == 0 {
		// https://tools.ietf.org/html/rfc5391
		t = 8000
	}
	return t
}

func (self *Stream) makeCodecData() (err error) {
	var sequenceNumber uint16
	sequenceNumber = 0
	media := self.Sdp

	// jpeg payload is 26
	if media.PayloadType >= 26 && media.PayloadType <= 127 {
		switch media.Type {
		case av.H264:
			for _, nalu := range media.SpropParameterSets {
				if len(nalu) > 0 {
					self.handleH264Payload(sequenceNumber, 0, nalu)
				}
			}

			if len(self.sps) == 0 || len(self.pps) == 0 {
				if nalus, typ := codecparser.SplitAVCNALUs(media.Config); typ != codecparser.NALU_RAW {
					for _, nalu := range nalus {
						if len(nalu) > 0 {
							self.handleH264Payload(sequenceNumber, 0, nalu)
						}
					}
				}
			}

			if len(self.sps) > 0 && len(self.pps) > 0 {
				if self.CodecData, err = codecparser.NewCodecDataFromSPSAndPPS(self.sps, self.pps); err != nil {
					err = fmt.Errorf("rtsp: h264 sps/pps invalid: %s", err)
					return
				}
			} else {
				err = fmt.Errorf("rtsp: missing h264 sps or pps")
				return
			}

		case av.H265:
			for _, nalu := range media.SpropParameterSets {
				if len(nalu) > 0 {
					self.handleH265Payload(sequenceNumber, 0, nalu)
				}
			}

			if len(self.sps) > 0 && len(self.pps) > 0 {
				if self.CodecData, err = codecparser.NewCodecDataFromVPSAndSPSAndPPS(self.vps, self.sps, self.pps); err != nil {
					err = fmt.Errorf("rtsp: h265 vps/sps/pps invalid: %s", err)
					return
				}
			} else {
				err = fmt.Errorf("rtsp: missing h265 vps or sps or pps")
				return
			}

		case av.JPEG:
			if self.CodecData, err = codecparser.NewCodecDataFromJPEG(self.width, self.height); err != nil {
				err = fmt.Errorf("rtsp: jpeg invalid: %s", err)
				return
			}

		case av.AAC:
			if len(media.Config) == 0 {
				err = fmt.Errorf("rtsp: aac sdp config missing")
				return
			}
			if self.CodecData, err = aacparser.NewCodecDataFromMPEG4AudioConfigBytes(media.Config); err != nil {
				err = fmt.Errorf("rtsp: aac sdp config invalid: %s", err)
				return
			}
		}

		if media.AVType == "audio" {
			self.CodecData = codec.NewPCMMulawCodecData()
		}

	} else {
		switch media.PayloadType {
		case 0:
			self.CodecData = codec.NewPCMMulawCodecData()

		case 8:
			self.CodecData = codec.NewPCMAlawCodecData()

		default:
			err = fmt.Errorf("rtsp: PayloadType=%d unsupported", media.PayloadType)
			return
		}
	}

	return
}

func (self *Stream) handleBuggyAnnexbH264Packet(sequenceNumber uint16, timestamp uint32, packet []byte) (isBuggy bool, err error) {
	if len(packet) >= 4 && packet[0] == 0 && packet[1] == 0 && packet[2] == 0 && packet[3] == 1 {
		isBuggy = true
		if nalus, typ := codecparser.SplitAVCNALUs(packet); typ != codecparser.NALU_RAW {
			for _, nalu := range nalus {
				if len(nalu) > 0 {
					if err = self.handleH264Payload(sequenceNumber, timestamp, nalu); err != nil {
						return
					}
				}
			}
		}
	}
	return
}

func (self *Stream) handleH264Payload(sequenceNumber uint16, timestamp uint32, packet []byte) (err error) {
	// fmt.Println(sequenceNumber, len(packet), hex.Dump(packet[:int(math.Min(float64(len(packet)), 10.0))]))
	// if self.fuBuffer != nil && timestamp != self.futimestamp {
	// 	if err = self.handleH264Payload(self.fusequenceNumber, self.futimestamp, self.fuBuffer); err != nil {
	// 		self.fuBuffer = nil
	// 		return
	// 	} else {
	// 		self.fuBuffer = nil
	// 	}
	// }

	if len(packet) < 2 {
		err = fmt.Errorf("rtp: h264 packet too short")
		return
	}

	var isBuggy bool
	if isBuggy, err = self.handleBuggyAnnexbH264Packet(sequenceNumber, timestamp, packet); isBuggy {
		return
	}

	naluType := packet[0] & 0x1f
	/*
		Table 7-1 – NAL unit type codes
		1   ￼Coded slice of a non-IDR picture
		5    Coded slice of an IDR picture
		6    Supplemental enhancement information (SEI)
		7    Sequence parameter set
		8    Picture parameter set
		1-23     NAL unit  Single NAL unit packet             5.6
		24       STAP-A    Single-time aggregation packet     5.7.1
		25       STAP-B    Single-time aggregation packet     5.7.1
		26       MTAP16    Multi-time aggregation packet      5.7.2
		27       MTAP24    Multi-time aggregation packet      5.7.2
		28       FU-A      Fragmentation unit                 5.8
		29       FU-B      Fragmentation unit                 5.8
		30-31    reserved                                     -
	*/
	switch {
	case naluType >= 1 && naluType <= 5:
		if naluType == 5 {
			self.pkt.IsKeyFrame = true
		}
		self.gotpkt = true

		b := make([]byte, 4+len(packet))
		pio.PutU32BE(b[0:4], uint32(len(packet)))
		copy(b[4:], packet)
		self.pkt.Data = b

		// raw nalu to avcc
		//self.pkt.Data = packet
		self.timestamp = timestamp

		self.pkt.SequenceIdx = sequenceNumber
		self.pkt.Timestamp = timestamp

	case naluType == 7: // sps
		if self.client != nil && self.client.DebugRtp {
			fmt.Println("rtsp: got sps")
		}
		if len(self.sps) == 0 {
			self.sps = packet
			self.makeCodecData()
		} else if bytes.Compare(self.sps, packet) != 0 {
			self.spsChanged = true
			self.sps = packet
			if self.client != nil && self.client.DebugRtp {
				fmt.Println("rtsp: sps changed")
			}
		}

	case naluType == 8: // pps
		if self.client != nil && self.client.DebugRtp {
			fmt.Println("rtsp: got pps")
		}
		if len(self.pps) == 0 {
			self.pps = packet
			self.makeCodecData()
		} else if bytes.Compare(self.pps, packet) != 0 {
			self.ppsChanged = true
			self.pps = packet
			if self.client != nil && self.client.DebugRtp {
				fmt.Println("rtsp: pps changed")
			}
		}

	case naluType == 28: // FU-A
		/*
			0                   1                   2                   3
			0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
			+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			| FU indicator  |   FU header   |                               |
			+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               |
			|                                                               |
			|                         FU payload                            |
			|                                                               |
			|                               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			|                               :...OPTIONAL RTP padding        |
			+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			Figure 14.  RTP payload format for FU-A

			The FU indicator octet has the following format:
			+---------------+
			|0|1|2|3|4|5|6|7|
			+-+-+-+-+-+-+-+-+
			|F|NRI|  Type   |
			+---------------+


			The FU header has the following format:
			+---------------+
			|0|1|2|3|4|5|6|7|
			+-+-+-+-+-+-+-+-+
			|S|E|R|  Type   |
			+---------------+

			S: 1 bit
			When set to one, the Start bit indicates the start of a fragmented
			NAL unit.  When the following FU payload is not the start of a
			fragmented NAL unit payload, the Start bit is set to zero.

			E: 1 bit
			When set to one, the End bit indicates the end of a fragmented NAL
			unit, i.e., the last byte of the payload is also the last byte of
			the fragmented NAL unit.  When the following FU payload is not the
			last fragment of a fragmented NAL unit, the End bit is set to
			zero.

			R: 1 bit
			The Reserved bit MUST be equal to 0 and MUST be ignored by the
			receiver.

			Type: 5 bits
			The NAL unit payload type as defined in table 7-1 of [1].
		*/
		fuIndicator := packet[0]
		fuHeader := packet[1]
		isStart := fuHeader&0x80 != 0
		isEnd := fuHeader&0x40 != 0

		// fmt.Println(isEnd == self.marker, isEnd, self.marker)

		// if packet[0] == 0x5c && packet[1] == 0x41 {
		// 	fmt.Println(hex.Dump(packet[:32]), isStart, isEnd)
		// 	os.Exit(1)
		// }
		// fmt.Println(isStart, isEnd)
		if isStart || self.fuBuffer == nil {
			self.fuStarted = true
			self.futimestamp = timestamp
			self.fusequenceNumber = sequenceNumber
			self.fuBuffer = []byte{fuIndicator&0xe0 | fuHeader&0x1f}
		}

		if self.fuStarted {
			self.fuBuffer = append(self.fuBuffer, packet[2:]...)
			// fmt.Println(sequenceNumber, len(packet))
			if isEnd || self.marker {
				// fmt.Println("marker")
				self.fuStarted = false
				if err = self.handleH264Payload(sequenceNumber, timestamp, self.fuBuffer); err != nil {
					self.fuBuffer = nil
					return
				}
				self.fuBuffer = nil
			}
		}
		// if isStart {
		// 	self.fuStarted = true
		// 	self.fuBuffer = []byte{fuIndicator&0xe0 | fuHeader&0x1f}
		// }
		// if self.fuStarted {
		// 	self.fuBuffer = append(self.fuBuffer, packet[2:]...)
		// 	if isEnd {
		// 		self.fuStarted = false
		// 		if err = self.handleH264Payload(sequenceNumber, timestamp, self.fuBuffer); err != nil {
		// 			return
		// 		}
		// 	}
		// }

	case naluType == 24: // STAP-A
		/*
			0                   1                   2                   3
			0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
			+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			|                          RTP Header                           |
			+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			|STAP-A NAL HDR |         NALU 1 Size           | NALU 1 HDR    |
			+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			|                         NALU 1 Data                           |
			:                                                               :
			+               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			|               | NALU 2 Size                   | NALU 2 HDR    |
			+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			|                         NALU 2 Data                           |
			:                                                               :
			|                               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			|                               :...OPTIONAL RTP padding        |
			+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

			Figure 7.  An example of an RTP packet including an STAP-A
			containing two single-time aggregation units
		*/
		packet = packet[1:]
		for len(packet) >= 2 {
			size := int(packet[0])<<8 | int(packet[1])
			if size+2 > len(packet) {
				break
			}
			if err = self.handleH264Payload(sequenceNumber, timestamp, packet[2:size+2]); err != nil {
				return
			}
			packet = packet[size+2:]
		}
		return

	case naluType >= 6 && naluType <= 23: // other single NALU packet
	case naluType == 25: // STAB-B
	case naluType == 26: // MTAP-16
	case naluType == 27: // MTAP-24
	case naluType == 28: // FU-B

	default:
		err = fmt.Errorf("rtsp: unsupported H264 naluType=%d", naluType)
		return
	}

	return
}

func (self *Stream) handleH265Payload(sequenceNumber uint16, timestamp uint32, packet []byte) (err error) {

	if len(packet) < 2 {
		err = fmt.Errorf("rtp: h265 packet too short")
		return
	}

	var naluType byte

	/*
		+---------------+---------------+
		|0|1|2|3|4|5|6|7|0|1|2|3|4|5|6|7|
		+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		|F|   Type    |  LayerId  | TID |
		+-------------+-----------------+
	*/
	naluType = (packet[0] >> 1) & 0x3F

	//fmt.Println("packet len ", len(packet))
	//fmt.Println("naluType ", naluType)

	/*
		NAL unit type codes
		NAL_UNIT_CODED_SLICE_TRAIL_N = 0,   // 0
		NAL_UNIT_CODED_SLICE_TRAIL_R,   // 1

		NAL_UNIT_CODED_SLICE_TSA_N,     // 2
		NAL_UNIT_CODED_SLICE_TLA,       // 3   // Current name in the spec: TSA_R

		NAL_UNIT_CODED_SLICE_STSA_N,    // 4
		NAL_UNIT_CODED_SLICE_STSA_R,    // 5

		NAL_UNIT_CODED_SLICE_RADL_N,    // 6
		NAL_UNIT_CODED_SLICE_DLP,       // 7 // Current name in the spec: RADL_R

		NAL_UNIT_CODED_SLICE_RASL_N,    // 8
		NAL_UNIT_CODED_SLICE_TFD,       // 9 // Current name in the spec: RASL_R
		NAL_UNIT_RESERVED_10,
		...
		NAL_UNIT_RESERVED_15, NAL_UNIT_CODED_SLICE_BLA,       // 16   // Current name in the spec: BLA_W_LP
		NAL_UNIT_CODED_SLICE_BLA,       // 16   // Current name in the spec: BLA_W_LP
		NAL_UNIT_CODED_SLICE_BLANT,     // 17   // Current name in the spec: BLA_W_DLP
		NAL_UNIT_CODED_SLICE_BLA_N_LP,  // 18
		NAL_UNIT_CODED_SLICE_IDR,       // 19  // Current name in the spec: IDR_W_DLP
		NAL_UNIT_CODED_SLICE_IDR_N_LP,  // 20
		NAL_UNIT_CODED_SLICE_CRA,       // 21
		...
		NAL_UNIT_VPS,                   // 32
		NAL_UNIT_SPS,                   // 33
		NAL_UNIT_PPS,                   // 34
		NAL_UNIT_ACCESS_UNIT_DELIMITER, // 35
		NAL_UNIT_EOS,                   // 36
		NAL_UNIT_EOB,                   // 37
		NAL_UNIT_FILLER_DATA,           // 38
		NAL_UNIT_SEI,                   // 39 Prefix SEI
		NAL_UNIT_SEI_SUFFIX,            // 40 Suffix SEI
		...
		NAL_UNIT_UNSPECIFIED_63,
		NAL_UNIT_INVALID,
	*/

	switch {
	case naluType >= 0 && naluType <= 19:
		//fmt.Println("NAL UNIT SLICE")
		if naluType == 19 {
			self.pkt.IsKeyFrame = true
		}

		self.gotpkt = true
		b := make([]byte, 4+len(packet))
		pio.PutU32BE(b[0:4], uint32(len(packet)))
		copy(b[4:], packet)
		self.pkt.Data = b

		// raw nalu to hvcc
		//self.pkt.Data = packet

		self.timestamp = timestamp

		self.pkt.SequenceIdx = sequenceNumber
		self.pkt.Timestamp = timestamp

	case naluType == 32: // NAL UNIT VPS
		//fmt.Println("NAL UNIT VPS")
		if self.client != nil && self.client.DebugRtp {
			fmt.Println("rtsp: got vps")
		}
		if len(self.vps) == 0 {
			self.vps = packet
			self.makeCodecData()
		} else if bytes.Compare(self.vps, packet) != 0 {
			self.vpsChanged = true
			self.vps = packet
			if self.client != nil && self.client.DebugRtp {
				fmt.Println("rtsp: vps changed")
			}
		}

	case naluType == 33: // NAL UNIT SPS
		//fmt.Println("NAL UNIT SPS")
		if self.client != nil && self.client.DebugRtp {
			fmt.Println("rtsp: got sps")
		}
		if len(self.sps) == 0 {
			self.sps = packet
			self.makeCodecData()
		} else if bytes.Compare(self.sps, packet) != 0 {
			self.spsChanged = true
			self.sps = packet
			if self.client != nil && self.client.DebugRtp {
				fmt.Println("rtsp: sps changed")
			}
		}

	case naluType == 34: // NAL UNIT PPS
		//fmt.Println("NAL UNIT PPS")
		if self.client != nil && self.client.DebugRtp {
			fmt.Println("rtsp: got pps")
		}
		if len(self.pps) == 0 {
			self.pps = packet
			self.makeCodecData()
		} else if bytes.Compare(self.pps, packet) != 0 {
			self.ppsChanged = true
			self.pps = packet
			if self.client != nil && self.client.DebugRtp {
				fmt.Println("rtsp: pps changed")
			}
		}

	case naluType == 49: // FU
		/*
			0                   1                   2                   3
			0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
			+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			|          PayloadHdr           |   FU header   | DONL(optional)|
			+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-|
			| DONL(optional)|                                               |
			|-+-+-+-+-+-+-+-+                                               |
			|                         FU payload                            |
			|                                                               |
			|                               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			|                               :...OPTIONAL RTP padding        |
			+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

			Figure 9 The structure of an FU

			The FU header consists of an S bit, an E bit, and a 6-bit FuType
			field, as shown in Figure 10.
			+---------------+
			|0|1|2|3|4|5|6|7|
			+-+-+-+-+-+-+-+-+
			|S|E|  FuType  |
			+---------------+

			Figure 10   The structure of FU header

			S: 1 bit
				When set to 1, the S bit indicates the start of a fragmented NAL
				unit, i.e., the first byte of the FU payload is also the first
				byte of the payload of the fragmented NAL unit.  When the FU
				payload is not the start of the fragmented NAL unit payload, the S
				bit MUST be set to 0.

			E: 1 bit
				When set to 1, the E bit indicates the end of a fragmented NAL
				unit, i.e., the last byte of the payload is also the last byte of
				the fragmented NAL unit.  When the FU payload is not the last
				fragment of a fragmented NAL unit, the E bit MUST be set to 0.

			FuType: 6 bits
				The field FuType MUST be equal to the field Type of the fragmented
				NAL unit.
		*/

		//fmt.Println("FU")
		//fuPayloadHdr := packet[0]
		fuHeader := packet[2]
		isStart := fuHeader&0x80 != 0
		isEnd := fuHeader&0x40 != 0
		//fuType := fuHeader & 0x3F
		//fmt.Println("fuType ", fuType)
		//fmt.Println(isStart, isEnd)
		if isStart || self.fuBuffer == nil {
			self.fuStarted = true
			self.futimestamp = timestamp
			self.fusequenceNumber = sequenceNumber
			self.fuBuffer = []byte{fuHeader << 1}
			self.fuBuffer = append(self.fuBuffer, packet[1])
		}

		if self.fuStarted {
			self.fuBuffer = append(self.fuBuffer, packet[3:]...)
			//fmt.Println(sequenceNumber, len(packet))
			if isEnd || self.marker {
				//fmt.Println("marker")
				self.fuStarted = false
				if err = self.handleH265Payload(sequenceNumber, timestamp, self.fuBuffer); err != nil {
					self.fuBuffer = nil
					return
				}
				self.fuBuffer = nil
			}
		}

		// case naluType >= 2 && naluType <= 9:

		// default:
		// 	err = fmt.Errorf("rtsp: unsupported H265 naluType=%d", naluType)
		// 	fmt.Println(err)
		// 	err = nil
		// 	return
	}

	return
}

func (self *Stream) handleJPEGPayload(sequenceNumber uint16, timestamp uint32, packet []byte) (err error) {

	if len(packet) < 8 {
		err = fmt.Errorf("rtp/mjpeg packet too short.")
		return
	}

	/*
		0                   1                   2                   3
		0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
		+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		| Type-specific |              Fragment Offset                  |
		+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		|      Type     |       Q       |     Width     |     Height    |
		+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

		and then

		+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		|       Restart Interval        |F|L|       Restart Count       |
		+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

		and then in the first packet, there is this header

		+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		|      MBZ      |   Precision   |             Length            |
		+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		|                    Quantization Table Data                    |
		|                              ...                              |
		+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	*/

	// Parse the main JPEG header.
	var qtableLen, dri, hdrSize int

	off := packet[1]<<16 | packet[2]<<8 | packet[3] /* fragment byte offset */
	types := packet[4]                              /* id of jpeg decoder params */
	q := packet[5]                                  /* quantization factor (or table id) */
	w := packet[6]                                  /* frame width in 8 pixel blocks */
	h := packet[7]                                  /* frame height in 8 pixel blocks */
	offset := 8

	if types&0x40 != 0 {
		dri = int(packet[8]<<8 | packet[9])
		offset += 4
	}

	/* Parse the quantization table header. */
	if off == 0 {
		/* Start of JPEG data packet. */
		var newQtables [128]uint8
		hdr := make([]byte, 1024)

		if q > 127 {
			precision := packet[offset+1]
			qtableLen := packet[offset+2] | packet[offset+3]
			offset += 4

			if precision != 0 {
				fmt.Println("Only 8-bit precision is supported.")
			}

			if qtableLen > 0 {
				fmt.Printf("qtableLen : %d\n", qtableLen)
			} else {
				fmt.Println("qtalbleLen minus")
			}
		} else { /* q <= 127 */
			if q == 0 || q > 99 {
				fmt.Printf("Reserved q value %d\n", q)
				return
			}

			self.width = uint(w) * 8
			self.height = uint(h) * 8
			self.makeCodecData()

			// create default qtables
			newQtables = createDefaultQtables(q)
			qtableLen = len(newQtables)
		}

		/* Copy JPEG header to frame buffer. */
		if self.createTable == false {
			/* Generate a frame and scan headers that can be prepended to the
			 * RTP/JPEG data payload to produce a JPEG compressed image in
			 * interchange format. */
			hdrSize = jpegCreateHeader(hdr, len(hdr), uint32(types), uint16(w), uint16(h), newQtables, qtableLen/64, dri)

			//fmt.Println("copy JPEG header to frame buffer.", hdrSize)
			self.fuBuffer = append(self.fuBuffer, hdr[0:hdrSize]...)
			self.createTable = true
		}
	}

	/* Copy data to frame buffer. */
	//fmt.Println("copy data to farme buffer.", len(packet))
	self.fuBuffer = append(self.fuBuffer, packet[offset:]...)

	if self.marker {
		if self.flag&RtpFlagMarker != 0 {
			/* End of JPEG data packet. */
			var buf = []byte{0xff, EOI}
			/* Put EOI marker. */
			self.fuBuffer = append(self.fuBuffer, buf[0:]...)

			/* Prepare the JPEG packet. */
			self.futimestamp = timestamp
			self.fusequenceNumber = sequenceNumber
			self.pkt.Data = self.fuBuffer
			self.timestamp = timestamp
			self.pkt.SequenceIdx = sequenceNumber
			self.pkt.Timestamp = timestamp
			self.pkt.IsKeyFrame = true
			self.gotpkt = true
			self.fuBuffer = nil
			self.createTable = false
		}
	}
	return
}

func (self *Stream) handleRtpPacket(packet []byte) (err error) {
	// if self.isCodecDataChange() {
	// 	err = ErrCodecDataChange
	// 	return
	// }

	if self.client != nil && self.client.DebugRtp {
		fmt.Println("rtp: packet", self.CodecData.Type(), "len", len(packet))
		dumpsize := len(packet)
		if dumpsize > 32 {
			dumpsize = 32
		}
		fmt.Print(hex.Dump(packet[:dumpsize]))
	}

	/*
		0                   1                   2                   3
		0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
		+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		|V=2|P|X|  CC   |M|     PT      |       sequence number         |
		+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		|                           timestamp                           |
		+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		|           synchronization source (SSRC) identifier            |
		+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
		|            contributing source (CSRC) identifiers             |
		|                             ....                              |
		+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	*/
	if len(packet) < 8 {
		err = fmt.Errorf("rtp: packet too short")
		return
	}
	payloadOffset := 12 + int(packet[0]&0xf)*4
	if payloadOffset > len(packet) {
		err = fmt.Errorf("rtp: packet too short")
		return
	}
	sequenceNumber := binary.BigEndian.Uint16(packet[2:4])
	timestamp := binary.BigEndian.Uint32(packet[4:8])
	self.flag = 0
	self.marker = (packet[1] & 0x80) != 0
	if self.marker {
		self.flag |= RTP_FLAG_MARKER
	}

	extension := packet[0]&0x10 != 0
	if payloadOffset+4 > len(packet) {
		err = fmt.Errorf("rtp: packet too short")
		return
	}
	if extension {
		headers := binary.BigEndian.Uint16(packet[payloadOffset+2 : payloadOffset+4])
		// fmt.Println(headers)
		payloadOffset += 4 + int(4*headers)
		if payloadOffset > len(packet) {
			err = fmt.Errorf("rtp: packet too short")
			return
		}
	}
	payload := packet[payloadOffset:]

	// fmt.Println(packet[1] & 0x80)
	/*
		PT 	Encoding Name 	Audio/Video (A/V) 	Clock Rate (Hz) 	Channels 	Reference
		0	PCMU	A	8000	1	[RFC3551]
		1	Reserved
		2	Reserved
		3	GSM	A	8000	1	[RFC3551]
		4	G723	A	8000	1	[Vineet_Kumar][RFC3551]
		5	DVI4	A	8000	1	[RFC3551]
		6	DVI4	A	16000	1	[RFC3551]
		7	LPC	A	8000	1	[RFC3551]
		8	PCMA	A	8000	1	[RFC3551]
		9	G722	A	8000	1	[RFC3551]
		10	L16	A	44100	2	[RFC3551]
		11	L16	A	44100	1	[RFC3551]
		12	QCELP	A	8000	1	[RFC3551]
		13	CN	A	8000	1	[RFC3389]
		14	MPA	A	90000		[RFC3551][RFC2250]
		15	G728	A	8000	1	[RFC3551]
		16	DVI4	A	11025	1	[Joseph_Di_Pol]
		17	DVI4	A	22050	1	[Joseph_Di_Pol]
		18	G729	A	8000	1	[RFC3551]
		19	Reserved	A
		20	Unassigned	A
		21	Unassigned	A
		22	Unassigned	A
		23	Unassigned	A
		24	Unassigned	V
		25	CelB	V	90000		[RFC2029]
		26	JPEG	V	90000		[RFC2435]
		27	Unassigned	V
		28	nv	V	90000		[RFC3551]
		29	Unassigned	V
		30	Unassigned	V
		31	H261	V	90000		[RFC4587]
		32	MPV	V	90000		[RFC2250]
		33	MP2T	AV	90000		[RFC2250]
		34	H263	V	90000		[Chunrong_Zhu]
		35-71	Unassigned	?
		72-76	Reserved for RTCP conflict avoidance				[RFC3551]
		77-95	Unassigned	?
		96-127	dynamic	?			[RFC3551]
	*/
	//payloadType := packet[1]&0x7f

	switch self.Sdp.Type {
	case av.H264:
		if err = self.handleH264Payload(sequenceNumber, timestamp, payload); err != nil {
			return
		}
		// if marker != 0 && self.fuBuffer != nil {
		// 	if err = self.handleH264Payload(sequenceNumber, timestamp, self.fuBuffer); err != nil {
		// 		self.fuBuffer = nil
		// 		return
		// 	} else {
		// 		self.fuBuffer = nil
		// 	}
		// }

	case av.H265:
		if err = self.handleH265Payload(sequenceNumber, timestamp, payload); err != nil {
			return
		}

	case av.JPEG:
		if err = self.handleJPEGPayload(sequenceNumber, timestamp, payload); err != nil {
			fmt.Println(err)
			return
		}

	case av.AAC:
		if len(payload) < 4 {
			err = fmt.Errorf("rtp: aac packet too short")
			return
		}
		payload = payload[4:] // TODO: remove this hack
		self.gotpkt = true
		self.pkt.Data = payload
		self.pkt.SequenceIdx = sequenceNumber
		self.pkt.Timestamp = timestamp
		self.timestamp = timestamp

	default:
		self.gotpkt = true
		self.pkt.Data = payload
		self.pkt.SequenceIdx = sequenceNumber
		self.pkt.Timestamp = timestamp
		self.timestamp = timestamp
	}

	return
}

func (self *Client) Play() (err error) {
	req := Request{
		Method: "PLAY",
		Uri:    self.requestUri,
	}
	if len(self.session) > 0 {
		req.Header = append(req.Header, "Session: "+self.session)
	}
	if err = self.WriteRequest(req); err != nil {
		return
	}
	var res Response
	if res, err = self.ReadResponse(); err != nil {
		return
	}
	if self.DebugRtsp {
		fmt.Println(string(res.Body))
	}
	if self.allCodecDataReady() {
		self.stage = stageCodecDataDone
	} else {
		self.stage = stageWaitCodecData
	}
	return
}

func (self *Client) Teardown() (err error) {
	req := Request{
		Method: "TEARDOWN",
		Uri:    self.requestUri,
	}
	req.Header = append(req.Header, "Session: "+self.session)
	if err = self.WriteRequest(req); err != nil {
		return
	}
	return
}

func (self *Client) Close() (err error) {
	if self.RtspOverHTTP {
		if self.connForOverHTTP != nil {
			err = self.connForOverHTTP.Conn.Close()
		}
		err2 := self.conn.Conn.Close()
		if err != nil {
			return
		}
		if err2 != nil {
			return err2
		}
		return
	}

	return self.conn.Conn.Close()
}

func (self *Client) handleBlock(block []byte) (pkt av.Packet, ok bool, err error) {
	_, blockno, _ := self.parseBlockHeader(block)
	if blockno%2 != 0 {
		if self.DebugRtp {
			fmt.Println("rtsp: rtcp block len", len(block)-4)
		}
		return
	}

	i := blockno / 2
	if i >= len(self.streams) {
		err = fmt.Errorf("rtsp: block no=%d invalid", blockno)
		return
	}
	stream := self.streams[i]

	herr := stream.handleRtpPacket(block[4:])
	if herr != nil {
		if !self.SkipErrRtpBlock {
			err = herr
			return
		}
	}

	if stream.gotpkt {
		/*
			TODO: sync AV by rtcp NTP timestamp
			TODO: handle timestamp overflow
			https://tools.ietf.org/html/rfc3550
			A receiver can then synchronize presentation of the audio and video packets by relating
			their RTP timestamps using the timestamp pairs in RTCP SR packets.
		*/
		if stream.firsttimestamp == 0 {
			stream.firsttimestamp = stream.timestamp
		}
		stream.timestamp -= stream.firsttimestamp

		ok = true
		pkt = stream.pkt
		pkt.Time = time.Duration(stream.timestamp) * time.Second / time.Duration(stream.timeScale())
		pkt.Idx = int8(self.setupMap[i])

		if pkt.Time < stream.lasttime || pkt.Time-stream.lasttime > time.Minute*30 {
			err = fmt.Errorf("rtp: time invalid stream#%d time=%v lasttime=%v", pkt.Idx, pkt.Time, stream.lasttime)
			return
		}
		stream.lasttime = pkt.Time

		if self.DebugRtp {
			fmt.Println("rtp: pktout", pkt.Idx, pkt.Time, len(pkt.Data))
		}

		stream.pkt = av.Packet{}
		stream.gotpkt = false
	}

	return
}

func (self *Client) handleRtpPacketFromUDP(streamIdx int, rtpPacket []byte) (pkt av.Packet, ok bool, err error) {
	stream := self.streams[streamIdx]
	herr := stream.handleRtpPacket(rtpPacket)
	if herr != nil {
		if !self.SkipErrRtpBlock {
			err = herr
			return
		}
	}

	if stream.gotpkt {
		/*
			TODO: sync AV by rtcp NTP timestamp
			TODO: handle timestamp overflow
			https://tools.ietf.org/html/rfc3550
			A receiver can then synchronize presentation of the audio and video packets by relating
			their RTP timestamps using the timestamp pairs in RTCP SR packets.
		*/
		if stream.firsttimestamp == 0 {
			stream.firsttimestamp = stream.timestamp
		}

		if stream.timestamp < stream.firsttimestamp {
			if self.DebugRtp {
				fmt.Println("rtp: invalid range timestamp", stream.timestamp, stream.firsttimestamp)
			}

			stream.gotpkt = false
			return
		}

		stream.timestamp -= stream.firsttimestamp
		// fmt.Println(stream.timestamp, stream.firsttimestamp)

		// ignore packets

		ok = true
		pkt = stream.pkt
		pkt.Time = time.Duration(stream.timestamp) * time.Second / time.Duration(stream.timeScale())
		pkt.Idx = int8(self.setupMap[streamIdx])

		if pkt.Time < stream.lasttime {
			ok = false
			err = nil
			return
		}

		// ignore packets
		if stream.lasttime > pkt.Time {
			stream.gotpkt = false
			return
		}

		if pkt.Time-stream.lasttime > time.Minute*30 {
			fmt.Println(pkt.Time, stream.lasttime)
			err = fmt.Errorf("rtp: time invalid stream#%d time=%v lasttime=%v", pkt.Idx, pkt.Time, stream.lasttime)
			return
		}
		stream.lasttime = pkt.Time

		if self.DebugRtp {
			fmt.Println("rtp: pktout", pkt.Idx, pkt.Time, len(pkt.Data))
		}

		stream.pkt = av.Packet{}
		stream.gotpkt = false
	}

	return
}

/*
	go func(i int) {
		p := make([]byte, 2048)
		fmt.Println(i, self.RtspCon[i], rtpPort)
		for {
			_, remoteaddr, err := self.RtpCon[i].ReadFromUDP(p)
			err := self.streams[i].handleRtpPacket(p)
			// fmt.Printf("Read a message from %v %s \n", remoteaddr, p)
			// if err != nil {
			// 	fmt.Printf("Some error  %v", err)
			// 	continue
			// }
		}
	}(i)
	go func(i int) {
		p := make([]byte, 2048)
		fmt.Println(i, self.RtpCon[i], rtspPort)
		for {
			_, remoteaddr, err := self.RtspCon[i].ReadFromUDP(p)
			fmt.Printf("Read a message from %v %s \n", remoteaddr, p)
			if err != nil {
				fmt.Printf("Some error  %v", err)
				continue
			}
		}
	}(i)

*/

func (self *Client) readPacketUDP(streamIdx int) (pkt av.Packet, err error) {
	if err = self.SendRtpKeepalive(); err != nil {
		return
	}

	p := make([]byte, 4096)
	var len int
	//var remoteaddr *net.UDPAddr
	var ok bool
	for {
		for {
			len, _, err = self.RtpCon[streamIdx].ReadFromUDP(p)
			if err != nil {
				return
			}
			if len > 0 {
				break
			}
		}

		data := p[:len]

		//if pkt, ok, err = self.handleBlock(data); err != nil {
		if pkt, ok, err = self.handleRtpPacketFromUDP(streamIdx, data); err != nil {
			return
		}
		if ok {
			return
		}
	}
}

func (self *Client) readPacket() (pkt av.Packet, err error) {
	begin := time.Now()

	if err = self.SendRtpKeepalive(); err != nil {
		return
	}

	for {
		var res Response
		for {
			if res, err = self.poll(); err != nil {
				return
			}
			if len(res.Block) > 0 {
				break
			}
		}

		var ok bool
		if pkt, ok, err = self.handleBlock(res.Block); err != nil {
			return
		}
		if ok {
			return
		}
		if time.Now().Add(-time.Second * 30).After(begin) {
			err = errors.New("Close by timeout in readPacket")
			return
		}
	}

	return
}

func (self *Client) ReadPacket() (pkt av.Packet, err error) {
	if err = self.prepare(stageCodecDataDone); err != nil {
		return
	}
	pkt, err = self.readPacket()

	// if self.IsCodecDataChange() {
	// 	err = self.HandleCodecDataChange()
	// 	if err != nil {
	// 		return pkt, err
	// 	}
	// }
	return pkt, err
}

func (self *Client) ReadPacketUDP(streamIdx int) (pkt av.Packet, err error) {
	if err = self.prepare(stageCodecDataDone); err != nil {
		return
	}
	return self.readPacketUDP(streamIdx)
}

func Handler(h *avutil.RegisterHandler) {
	h.UrlDemuxer = func(uri string) (ok bool, demuxer av.DemuxCloser, err error) {
		if !strings.HasPrefix(uri, "rtsp://") {
			return
		}
		ok = true
		demuxer, err = Dial(uri)
		return
	}
}

